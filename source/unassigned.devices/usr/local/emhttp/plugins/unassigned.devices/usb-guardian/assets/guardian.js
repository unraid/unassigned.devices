(function () {
  'use strict';

  const runtime = window.UsbGuardianRuntime;
  if (!runtime || !runtime.apiUrl || !runtime.csrfToken) {
    return;
  }

  const translations = runtime.i18n && typeof runtime.i18n === 'object' ? runtime.i18n : {};
  const translationTemplates = Object.entries(translations).flatMap(([source, translated]) => {
    const names = [];
    let pattern = '';
    let offset = 0;
    const placeholders = /\{([A-Za-z][A-Za-z0-9_]*)\}/g;
    for (const match of source.matchAll(placeholders)) {
      pattern += source.slice(offset, match.index).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      pattern += '(.+?)';
      names.push(match[1]);
      offset = match.index + match[0].length;
    }
    if (!names.length) {
      return [];
    }
    pattern += source.slice(offset).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return [{ expression: new RegExp(`^${pattern}$`), names, translated }];
  });

  function tr(value) {
    if (typeof value !== 'string' || !value) {
      return value;
    }
    if (typeof translations[value] === 'string') {
      return translations[value];
    }
    for (const template of translationTemplates) {
      const match = value.match(template.expression);
      if (!match) {
        continue;
      }
      const fields = Object.fromEntries(template.names.map((name, index) => [name, match[index + 1]]));
      return template.translated.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (_placeholder, name) => fields[name] ?? '');
    }
    return value;
  }

  const STORAGE_ACTIVE = 'usb.guardian.active.v1';
  const STORAGE_SAFE = 'usb.guardian.safe.v1';
  const STORAGE_DISMISSED = 'usb.guardian.dismissed.v1';
  const STORAGE_AUTHORITY = 'usb.guardian.authority.v1';
  const SAFE_STATES = new Set(['completed']);
  const TERMINAL_STATES = new Set(['completed', 'failed']);
  const POLL_INTERVAL_MS = 1200;
  const LIST_THROTTLE_MS = 2500;
  const SAFE_WATCHDOG_MS = 2000;
  const SAFE_LEASE_MS = 5000;
  const SAFE_REQUEST_TIMEOUT_MS = 1500;
  const state = {
    devices: [],
    bootId: '',
    listRequest: null,
    lastListAt: 0,
    listError: '',
    checkingKeys: new Set(),
    enabled: true,
    authority: null,
    watchdogTimer: 0,
    leaseExpiryTimer: 0,
    watchdogRequest: null,
    jobs: new Map(),
    notices: new Map(),
  };

  const fallbackAdvice = {
    busy: 'Close the listed process or service, then check again.',
    open_files: 'Close the listed files and processes, then check again.',
    docker_bind: 'Stop the listed Docker container or remove its bind mount, then check again.',
    smb: 'Disconnect SMB clients that are using this device, then check again.',
    nfs: 'Disconnect NFS clients that are using this device, then check again.',
    smb_client: 'Disconnect SMB clients that are using this device, then check again.',
    nfs_client: 'Disconnect NFS clients that are using this device, then check again.',
    vm_passthrough: 'Shut down the listed VM and remove the USB or block-device mapping, then check again.',
    preclear: 'Wait for Preclear to finish or stop it safely, then check again.',
    preclear_running: 'Wait for Preclear to finish or stop it safely, then check again.',
    sibling_busy: 'Release the other disk in the same USB enclosure, then check again.',
    boot_device: 'The Unraid boot device must not be ejected.',
    boot: 'The Unraid boot device must not be ejected.',
    protected_boot: 'The Unraid boot device must not be ejected.',
    array_device: 'Array devices cannot be ejected by USB Guardian.',
    array: 'Array devices cannot be ejected by USB Guardian.',
    pool_device: 'Pool devices cannot be ejected by USB Guardian.',
    pool: 'Pool devices cannot be ejected by USB Guardian.',
    protected_pool: 'Pool devices cannot be ejected by USB Guardian.',
    composite_device: 'This composite USB device is not supported because ejecting it would remove non-storage interfaces.',
    composite: 'This composite USB device is not supported because ejecting it would remove non-storage interfaces.',
    ud_capability_unavailable: 'Install a compatible official Unassigned Devices release, then check again.',
    ud_version: 'Install a compatible official Unassigned Devices release, then check again.',
    smb_nfs_client: 'Disconnect SMB/NFS clients that are using this device, then check again.',
  };

  function loadJson(key, fallback) {
    try {
      const value = JSON.parse(window.localStorage.getItem(key) || 'null');
      return value === null ? fallback : value;
    } catch (_error) {
      return fallback;
    }
  }

  function saveJson(key, value) {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (_error) {
      // Status remains available for this page even when local storage is unavailable.
    }
  }

  function markJobDismissed(jobId) {
    if (!jobId) {
      return;
    }
    const dismissed = loadJson(STORAGE_DISMISSED, []);
    const jobIds = Array.isArray(dismissed) ? dismissed.filter((value) => typeof value === 'string') : [];
    saveJson(STORAGE_DISMISSED, [...new Set([jobId, ...jobIds])].slice(0, 20));
  }

  function parseAuthority(value, generation = undefined) {
    if (!value || typeof value !== 'object'
      || value.schema_version !== 1
      || typeof value.boot_id !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value.boot_id)
      || typeof value.job_id !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.job_id)
      || !Number.isSafeInteger(value.generation)
      || value.generation < 1
      || (generation !== undefined && generation !== value.generation)) {
      return null;
    }
    return {
      schema_version: 1,
      boot_id: value.boot_id,
      job_id: value.job_id,
      generation: value.generation,
    };
  }

  function authorityFromPayload(payload) {
    return parseAuthority(payload?.authority, payload?.generation);
  }

  function authorityMatchesSafe(authority, safe) {
    return Boolean(authority && safe
      && safe.bootId === authority.boot_id
      && safe.jobId === authority.job_id
      && safe.generation === authority.generation);
  }

  function stopSafeWatchdog() {
    window.clearTimeout(state.watchdogTimer);
    window.clearTimeout(state.leaseExpiryTimer);
    state.watchdogTimer = 0;
    state.leaseExpiryTimer = 0;
  }

  function clearSafeApprovalVisuals() {
    removeNotice('safe');
    const modal = document.getElementById('usb-guardian-modal-layer');
    if (modal?.dataset.guardianSafeApproval === 'true') {
      closeModal();
    }
    stopSafeWatchdog();
    syncControls();
  }

  function revokeSafeApproval(title, message, noticeId = 'safe-revoked') {
    const safe = loadJson(STORAGE_SAFE, null);
    const modal = document.getElementById('usb-guardian-modal-layer');
    const hadSafe = Boolean(safe || state.notices.has('safe') || modal?.dataset.guardianSafeApproval === 'true');
    window.localStorage.removeItem(STORAGE_SAFE);
    clearSafeApprovalVisuals();
    if (title && hadSafe) {
      setNotice(noticeId, {
        kind: 'warning',
        title,
        message: `${message} Do not unplug the device.`,
        dismissible: true,
      });
    }
  }

  function dismissSafeApproval() {
    const safe = loadJson(STORAGE_SAFE, null);
    if (safe?.jobId) {
      markJobDismissed(safe.jobId);
    }
    window.localStorage.removeItem(STORAGE_SAFE);
    clearSafeApprovalVisuals();
  }

  function applyAuthority(authority, publish = true) {
    state.authority = authority;
    if (publish) {
      if (authority) {
        saveJson(STORAGE_AUTHORITY, authority);
      } else {
        window.localStorage.removeItem(STORAGE_AUTHORITY);
      }
    }
    const safe = loadJson(STORAGE_SAFE, null);
    if (safe && !authorityMatchesSafe(authority, safe)) {
      revokeSafeApproval(
        'Safe-to-unplug approval is no longer current',
        'A newer or unverifiable safe-eject authority was detected.',
        'safe-authority-revoked',
      );
    }
  }

  async function api(action, fields = {}, options = {}) {
    const body = new URLSearchParams({ action, csrf_token: runtime.csrfToken, ...fields });
    const timeoutMs = Number.isFinite(options.timeoutMs) ? Math.max(1, options.timeoutMs) : 0;
    const controller = timeoutMs ? new AbortController() : null;
    const timeout = controller ? window.setTimeout(() => controller.abort(), timeoutMs) : 0;
    let response;
    try {
      response = await window.fetch(runtime.apiUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        body: body.toString(),
        cache: 'no-store',
        signal: controller?.signal,
      });
    } catch (error) {
      if (error?.name === 'AbortError') {
        throw new Error(`USB Guardian ${action} verification timed out.`);
      }
      throw error;
    } finally {
      if (timeout) {
        window.clearTimeout(timeout);
      }
    }
    let payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw Object.assign(new Error(tr('Unraid rejected the request. Refresh this page and try again.')), { status: response.status });
    }
    if (!response.ok || payload.ok !== true) {
      const error = new Error(payload?.error?.message || 'USB Guardian request failed.');
      error.status = response.status;
      error.details = payload?.error?.details || {};
      error.requestId = payload?.error?.request_id || '';
      throw error;
    }
    return payload.data;
  }

  function normalizeDeviceKey(value) {
    if (typeof value !== 'string') {
      return '';
    }
    const normalized = value.trim().toLowerCase().replace(/^\/dev\//, '');
    const scsiPartition = normalized.match(/^(sd[a-z]+)[0-9]+$/);
    return scsiPartition ? scsiPartition[1] : normalized;
  }

  function deviceKeys(device) {
    const values = [];
    for (const field of ['devX', 'kernel_name', 'kernel_device', 'kernel_dev', 'devnode', 'device', 'name', 'block_device']) {
      if (typeof device[field] === 'string') {
        values.push(device[field]);
      }
    }
    for (const field of ['aliases', 'device_aliases']) {
      if (Array.isArray(device[field])) {
        values.push(...device[field]);
      }
    }
    return [...new Set(values.map(normalizeDeviceKey).filter(Boolean))];
  }

  function deviceName(device) {
    for (const field of ['display_name', 'label', 'model', 'devX', 'kernel_name', 'device', 'kernel_device', 'kernel_dev', 'name']) {
      if (typeof device[field] === 'string' && device[field].trim()) {
        return device[field].trim();
      }
    }
    return 'USB device';
  }

  function deviceIdentity(device) {
    if (!device || typeof device !== 'object') {
      return {};
    }
    const identity = {};
    for (const field of ['kernel_name', 'major_minor', 'diskseq', 'serial', 'usb_path', 'usb_vid', 'usb_pid', 'usb_serial', 'vendor', 'model']) {
      if (typeof device[field] === 'string' && device[field]) {
        identity[field] = device[field];
      }
    }
    return identity;
  }

  function leaseIdentity(value) {
    if (!value || typeof value !== 'object'
      || typeof value.usb_path !== 'string'
      || !value.usb_path
      || typeof value.usb_vid !== 'string'
      || !/^[0-9a-f]{4}$/.test(value.usb_vid)
      || typeof value.usb_pid !== 'string'
      || !/^[0-9a-f]{4}$/.test(value.usb_pid)
      || (value.usb_serial !== undefined && typeof value.usb_serial !== 'string')) {
      return null;
    }
    return {
      usb_path: value.usb_path,
      usb_vid: value.usb_vid,
      usb_pid: value.usb_pid,
      usb_serial: value.usb_serial || '',
    };
  }

  function leaseIdentityMatches(expected, actual) {
    return Boolean(expected && actual
      && expected.usb_path === actual.usb_path
      && expected.usb_vid === actual.usb_vid
      && expected.usb_pid === actual.usb_pid
      && expected.usb_serial === actual.usb_serial);
  }

  function samePhysicalDevice(identity, device) {
    const current = deviceIdentity(device);
    if (identity.usb_path && current.usb_path && identity.usb_path === current.usb_path) return true;
    if (identity.usb_serial && current.usb_serial && identity.usb_serial === current.usb_serial) return true;
    if (identity.serial && current.serial && identity.serial === current.serial) return true;
    return Boolean(identity.kernel_name && current.kernel_name && identity.kernel_name === current.kernel_name
      && identity.vendor === current.vendor && identity.model === current.model);
  }

  function deviceToken(device) {
    for (const field of ['token', 'opaque_token', 'target']) {
      if (typeof device[field] === 'string' && device[field]) {
        return device[field];
      }
    }
    return '';
  }

  function eligibility(device) {
    const nested = device.eligibility && typeof device.eligibility === 'object' ? device.eligibility : {};
    const eligible = typeof device.eligible === 'boolean' ? device.eligible === true : nested.eligible === true;
    return {
      eligible,
      reasons: Array.isArray(device.reasons) ? device.reasons : (Array.isArray(nested.reasons) ? nested.reasons : []),
    };
  }

  function reasonParts(reason) {
    if (typeof reason === 'string') {
      return { code: '', message: tr(reason), detail: '', advice: '', blockers: [] };
    }
    if (!reason || typeof reason !== 'object') {
      return { code: '', message: tr('Eligibility check failed.'), detail: '', advice: '', blockers: [] };
    }
    const code = typeof reason.code === 'string' ? reason.code : '';
    const rawMessage = typeof reason.message === 'string' && reason.message ? reason.message : (code || 'Eligibility check failed.');
    const rawAdvice = typeof reason.advice === 'string' && reason.advice ? reason.advice : (fallbackAdvice[code] || '');
    const translatedMessage = tr(rawMessage);
    const translatedAdvice = tr(rawAdvice);
    const genericMessage = translations[`@reason.${code}.message`];
    const genericAdvice = translations[`@reason.${code}.advice`];
    return {
      code,
      message: translatedMessage !== rawMessage ? translatedMessage : (genericMessage || rawMessage),
      detail: typeof reason.detail === 'string' ? reason.detail : '',
      advice: translatedAdvice !== rawAdvice ? translatedAdvice : (genericAdvice || rawAdvice),
      blockers: Array.isArray(reason.blockers) ? reason.blockers : [],
    };
  }

  function createElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
      element.className = className;
    }
    if (text !== undefined) {
      element.textContent = tr(text);
    }
    return element;
  }

  function closeModal() {
    const existing = document.getElementById('usb-guardian-modal-layer');
    if (existing) {
      existing.remove();
    }
  }

  function showModal(options) {
    closeModal();
    const layer = createElement('div', 'usb-guardian-modal-layer');
    layer.id = 'usb-guardian-modal-layer';
    const dialog = createElement('div', 'usb-guardian-modal');
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'usb-guardian-modal-title');

    const header = createElement('div', 'usb-guardian-modal-header');
    const title = createElement('h2', '', options.title);
    title.id = 'usb-guardian-modal-title';
    const close = createElement('button', 'usb-guardian-icon-button');
    close.type = 'button';
    close.setAttribute('aria-label', tr('Close'));
    close.title = tr('Close');
    close.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
    close.addEventListener('click', closeModal);
    header.append(title, close);

    const body = createElement('div', 'usb-guardian-modal-body');
    if (options.message) {
      body.append(createElement('p', '', options.message));
    }
    if (Array.isArray(options.reasons) && options.reasons.length) {
      const list = createElement('div', 'usb-guardian-reason-list');
      options.reasons.forEach((rawReason) => {
        const reason = reasonParts(rawReason);
        const item = createElement('div', 'usb-guardian-reason');
        const heading = createElement('strong', '', reason.message);
        item.append(heading);
        if (reason.detail) {
          item.append(createElement('div', 'usb-guardian-reason-detail', reason.detail));
        }
        reason.blockers.forEach((blocker) => {
          if (!blocker || typeof blocker !== 'object') {
            return;
          }
          const parts = [];
          if (Number.isInteger(blocker.pid) && blocker.pid > 0) parts.push(`PID ${blocker.pid}`);
          if (typeof blocker.process === 'string' && blocker.process) parts.push(blocker.process);
          if (typeof blocker.kind === 'string' && blocker.kind) parts.push(blocker.kind);
          if (typeof blocker.path === 'string' && blocker.path) parts.push(blocker.path);
          if (typeof blocker.detail === 'string' && blocker.detail) parts.push(blocker.detail);
          if (parts.length) {
            item.append(createElement('div', 'usb-guardian-reason-detail', parts.join(' | ')));
          }
        });
        if (reason.advice) {
          const advice = createElement('div', 'usb-guardian-reason-advice');
          advice.append(createElement('i', 'fa fa-wrench'));
          advice.append(document.createTextNode(' ' + tr(reason.advice)));
          item.append(advice);
        }
        list.append(item);
      });
      body.append(list);
    }

    const footer = createElement('div', 'usb-guardian-modal-actions');
    for (const action of options.actions || []) {
      const button = createElement('button', action.primary ? 'usb-guardian-primary' : '', action.label);
      button.type = 'button';
      if (action.icon) {
        button.textContent = '';
        button.innerHTML = `<i class="fa ${action.icon}" aria-hidden="true"></i> `;
        button.append(document.createTextNode(tr(action.label)));
      }
      button.addEventListener('click', async () => {
        if (action.close !== false) {
          closeModal();
        }
        if (action.handler) {
          await action.handler();
        }
      });
      footer.append(button);
    }
    dialog.append(header, body, footer);
    layer.append(dialog);
    layer.addEventListener('click', (event) => {
      if (event.target === layer) {
        closeModal();
      }
    });
    document.body.append(layer);
    close.focus();
    return layer;
  }

  function showIneligible(device, key = '') {
    const checked = eligibility(device);
    showModal({
      title: `Cannot safely eject ${deviceName(device)}`,
      message: checked.reasons.length ? '' : 'USB Guardian did not receive a safe-eject approval from the backend.',
      reasons: checked.reasons,
      actions: [
        {
          label: 'Check again',
          icon: 'fa-refresh',
          primary: true,
          handler: () => key ? inspectDeviceOnDemand(key, deviceName(device)) : refreshDevices(true),
        },
        { label: 'Close', close: true },
      ],
    });
  }

  function showConfirmation(device) {
    showModal({
      title: `Safely eject ${deviceName(device)}?`,
      message: 'USB safe eject will check for active use, unmount the drive and disconnect it. Wait for Safe to unplug before removing it.',
      actions: [
        { label: 'Cancel', close: true },
        { label: 'Safe eject', icon: 'fa-eject', primary: true, handler: () => startEject(device) },
      ],
    });
  }

  function setNotice(id, notice) {
    state.notices.set(id, notice);
    renderNotices();
  }

  function removeNotice(id) {
    state.notices.delete(id);
    renderNotices();
  }

  function renderNotices() {
    const host = document.getElementById('usb-guardian-live');
    if (!host) {
      return;
    }
    host.replaceChildren();
    for (const [id, notice] of state.notices) {
      const element = createElement('div', `usb-guardian-notice usb-guardian-notice-${notice.kind || 'info'}`);
      const iconNames = { success: 'fa-check-circle', error: 'fa-exclamation-circle', warning: 'fa-exclamation-triangle', progress: 'fa-circle-o-notch fa-spin', info: 'fa-info-circle' };
      element.append(createElement('i', `fa ${iconNames[notice.kind] || iconNames.info} usb-guardian-notice-icon`));
      const copy = createElement('div', 'usb-guardian-notice-copy');
      copy.append(createElement('strong', '', notice.title || 'USB Guardian'));
      if (notice.message) {
        copy.append(createElement('div', '', notice.message));
      }
      element.append(copy);
      if (notice.action) {
        const action = createElement('button', 'usb-guardian-notice-action', notice.action.label);
        action.type = 'button';
        action.addEventListener('click', notice.action.handler);
        element.append(action);
      }
      if (notice.dismissible) {
        const dismiss = createElement('button', 'usb-guardian-icon-button usb-guardian-notice-dismiss');
        dismiss.type = 'button';
        dismiss.title = tr('Dismiss');
        dismiss.setAttribute('aria-label', tr('Dismiss'));
        dismiss.innerHTML = '<i class="fa fa-times" aria-hidden="true"></i>';
        dismiss.addEventListener('click', () => {
          if (id === 'safe') {
            dismissSafeApproval();
          } else {
            removeNotice(id);
          }
        });
        element.append(dismiss);
      }
      host.append(element);
    }
  }

  function persistJobs() {
    saveJson(STORAGE_ACTIVE, [...state.jobs.values()].map((job) => ({
      jobId: job.jobId,
      bootId: job.bootId || state.bootId,
      name: job.name || 'USB device',
      deviceKeys: Array.isArray(job.deviceKeys) ? job.deviceKeys : [],
      identity: job.identity || {},
      acceptedGeneration: Number.isSafeInteger(job.acceptedGeneration) ? job.acceptedGeneration : 0,
    })));
  }

  function activeJobForKey(key) {
    for (const job of state.jobs.values()) {
      if ((job.deviceKeys || []).includes(key)) {
        return job;
      }
    }
    return null;
  }

  function deviceForKey(key) {
    const matches = state.devices.filter((device) => deviceKeys(device).includes(key));
    return matches.length === 1 ? matches[0] : null;
  }

  function showListErrorModal(key, rowName) {
    showModal({
      title: 'USB eligibility check unavailable',
      reasons: [{
        message: 'Eligibility check failed.',
        detail: state.listError,
        advice: `${state.listError} Do not unplug a USB storage device based on the current page state.`,
      }],
      actions: [
        { label: 'Check again', icon: 'fa-refresh', primary: true, handler: () => inspectDeviceOnDemand(key, rowName) },
        { label: 'Close' },
      ],
    });
  }

  async function inspectDeviceOnDemand(key, rowName) {
    if (!key || state.checkingKeys.has(key) || activeJobForKey(key)) {
      return;
    }
    state.checkingKeys.add(key);
    syncControls();
    try {
      const payload = await refreshDevices(true);
      if (!payload) {
        showListErrorModal(key, rowName);
        return;
      }
      const device = deviceForKey(key);
      if (!device) {
        showIneligible({
          display_name: rowName || key,
          eligible: false,
          reasons: [{
            code: 'inspection_failed',
            message: 'This Unassigned Devices row does not match exactly one supported USB storage device.',
            detail: `device=${key}`,
            advice: 'Refresh Unassigned Devices and confirm that this row is a directly attached USB storage disk, then try again.',
          }],
        }, key);
        return;
      }
      const checked = eligibility(device);
      if (checked.eligible && deviceToken(device)) {
        showConfirmation(device);
      } else {
        showIneligible(device, key);
      }
    } finally {
      state.checkingKeys.delete(key);
      syncControls();
    }
  }

  function controlSignature(key) {
    return [key, state.checkingKeys.has(key) ? '1' : '0', activeJobForKey(key)?.jobId || ''].join(';');
  }

  function syncControls() {
    document.querySelectorAll('.usb-guardian-control[data-guardian-device]').forEach((button) => {
      const key = normalizeDeviceKey(button.dataset.guardianDevice || '');
      const rowName = button.dataset.guardianName || key;
      const checking = state.checkingKeys.has(key);
      const active = activeJobForKey(key);
      const label = checking ? tr(`Checking ${rowName}`)
        : active ? tr('Safe eject in progress') : tr(`Safely eject ${rowName}`);
      button.hidden = !state.enabled;
      button.disabled = checking;
      button.classList.toggle('usb-guardian-control-progress', checking || !!active);
      button.title = label;
      button.setAttribute('aria-label', label);
      const icon = button.querySelector('i');
      if (icon) icon.className = checking || active ? 'fa fa-circle-o-notch fa-spin' : 'fa fa-eject';
      const status = button.parentElement.querySelector('.usb-guardian-control-status');
      if (status) status.textContent = checking || active ? label : '';
    });
  }

  function applyDevicePayload(payload) {
    state.devices = Array.isArray(payload?.devices) ? payload.devices.filter((item) => item && typeof item === 'object') : [];
    state.lastListAt = Date.now();
    state.listError = '';
    state.bootId = typeof payload?.meta?.boot_id === 'string' ? payload.meta.boot_id : '';
    removeNotice('list-error');
    discardStaleLocalState();
    expireSafeNoticeForReturnedDevice();
    syncControls();
    return payload;
  }

  async function refreshDevices(force) {
    if (!force && Date.now() - state.lastListAt < LIST_THROTTLE_MS) {
      syncControls();
      return;
    }
    if (state.listRequest) {
      return state.listRequest;
    }
    state.listRequest = (async () => {
      try {
        const payload = await api('list');
        return applyDevicePayload(payload);
      } catch (error) {
        state.lastListAt = Date.now();
        if (error.details?.code === 'plugin_disabled') {
          state.enabled = false;
          state.devices = [];
          state.listError = error.message;
          syncControls();
          revokeSafeApproval('', '');
          removeNotice('list-error');
          return null;
        }
        state.listError = error.message;
        syncControls();
        revokeSafeApproval('', '');
        setNotice('list-error', {
          kind: 'error',
          title: 'USB eligibility check unavailable',
          message: `${error.message} Do not unplug a USB storage device based on the current page state.`,
          action: { label: 'Check again', handler: () => refreshDevices(true) },
        });
        return null;
      } finally {
        state.listRequest = null;
      }
    })();
    return state.listRequest;
  }

  function discardStaleLocalState() {
    if (!state.bootId) {
      return;
    }
    for (const [jobId, job] of state.jobs) {
      if (job.bootId && job.bootId !== state.bootId) {
        state.jobs.delete(jobId);
        removeNotice(`job:${jobId}`);
      }
    }
    persistJobs();
    const safe = loadJson(STORAGE_SAFE, null);
    if (safe && safe.bootId !== state.bootId) {
      revokeSafeApproval(
        'Safe-to-unplug approval expired after a server restart',
        'The saved operation belongs to a different boot identity.',
        'safe-boot-revoked',
      );
    }
  }

  function expireSafeNoticeForReturnedDevice() {
    const safe = loadJson(STORAGE_SAFE, null);
    if (!safe || safe.bootId !== state.bootId || !safe.identity || !state.devices.some((device) => samePhysicalDevice(safe.identity, device))) {
      return;
    }
    revokeSafeApproval(
      `${safe.name || 'USB device'} was detected again`,
      'The previous safe-to-unplug approval has expired. Run safe eject again before unplugging it.',
      'safe-expired',
    );
  }

  async function startEject(device) {
    const token = deviceToken(device);
    if (!token) {
      showIneligible(device);
      return;
    }
    const name = deviceName(device);
    removeNotice('safe-expired');
    setNotice('starting', { kind: 'progress', title: `Starting safe eject for ${name}`, message: 'Validating the current device identity and eligibility.' });
    try {
      const result = await api('eject', { target: token });
      removeNotice('starting');
      window.localStorage.removeItem(STORAGE_SAFE);
      clearSafeApprovalVisuals();
      const authority = authorityFromPayload(result);
      const authorityAccepted = Boolean(authority
        && result.is_latest_job === true
        && result.job_id === authority.job_id);
      applyAuthority(authorityAccepted ? authority : null);
      const job = {
        jobId: result.job_id,
        bootId: result.boot_id || state.bootId,
        name,
        deviceKeys: deviceKeys(device),
        identity: deviceIdentity(device),
        acceptedGeneration: authorityAccepted ? authority.generation : 0,
        failures: 0,
      };
      state.jobs.set(job.jobId, job);
      persistJobs();
      syncControls();
      if (!authorityAccepted) {
        setNotice(`job:${job.jobId}`, {
          kind: 'error',
          title: `Cannot verify safe-eject authority for ${name}`,
          message: 'The request may be running, but its latest-job authority is missing or invalid. Do not unplug the device.',
        });
      }
      pollJob(job);
    } catch (error) {
      removeNotice('starting');
      const failedAuthority = authorityFromPayload(error?.details);
      if (failedAuthority
        && error?.details?.is_latest_job === true
        && error?.details?.job_id === failedAuthority.job_id) {
        applyAuthority(failedAuthority);
      }
      const reasons = Array.isArray(error?.details?.reasons) ? error.details.reasons : [];
      if (reasons.length) {
        showModal({
          title: `Cannot safely eject ${name}`,
          message: error.message,
          reasons,
          actions: [
            { label: 'Check again', icon: 'fa-refresh', primary: true, handler: () => refreshDevices(true) },
            { label: 'Close' },
          ],
        });
      }
      setNotice('start-error', {
        kind: 'error',
        title: `Safe eject did not start for ${name}`,
        message: `${error.message} The device is not safe to unplug.`,
        dismissible: true,
        action: { label: 'Check again', handler: () => refreshDevices(true) },
      });
    }
  }

  function statusMessage(status) {
    const phase = typeof status.phase === 'string' && status.phase ? status.phase.replaceAll('_', ' ') : 'working';
    const message = typeof status.message === 'string' ? status.message : '';
    const progress = Number.isFinite(status.progress) ? ` (${Math.max(0, Math.min(100, status.progress))}%)` : '';
    return message || `${phase}${progress}`;
  }

  async function verifyServerLeaseSnapshot(jobId, generation, identity) {
    const lease = await api('lease', {
      job_id: jobId,
      generation: String(generation),
    }, { timeoutMs: SAFE_REQUEST_TIMEOUT_MS });
    const authority = authorityFromPayload(lease);
    applyAuthority(authority);
    const job = lease?.job;
    const expectedIdentity = leaseIdentity(identity);
    const verifiedIdentity = leaseIdentity(lease?.identity);
    if (!authority
      || lease.boot_id !== authority.boot_id
      || (state.bootId && state.bootId !== authority.boot_id)
      || authority.job_id !== jobId
      || authority.generation !== generation
      || lease.is_latest_job !== true
      || lease.device_absent !== true
      || !job
      || job.job_id !== jobId
      || job.state !== 'completed'
      || job.terminal !== true
      || job.safe_to_unplug !== true
      || !leaseIdentityMatches(expectedIdentity, verifiedIdentity)) {
      throw new Error('The server no longer confirms this operation as the latest completed safe eject.');
    }
    return { authority, identity: verifiedIdentity };
  }

  async function finishJob(job, status) {
    const stateName = String(status.state || '').toLowerCase();
    const coreReportedSafe = status.safe_to_unplug === true && SAFE_STATES.has(stateName);
    let explicitlySafe = coreReportedSafe && status.authorityVerified === true;
    let verifiedLease = null;
    let authorityError = '';
    state.jobs.delete(job.jobId);
    persistJobs();
    removeNotice(`job:${job.jobId}`);
    syncControls();

    if (explicitlySafe) {
      setNotice(`job:${job.jobId}`, {
        kind: 'progress',
        title: `Verifying final safe-eject lease for ${job.name}`,
        message: 'Confirming the latest authority, completed job, and USB device absence.',
      });
      try {
        const identity = Object.keys(deviceIdentity(status.device)).length ? deviceIdentity(status.device) : (job.identity || {});
        verifiedLease = await verifyServerLeaseSnapshot(job.jobId, job.acceptedGeneration, identity);
      } catch (error) {
        explicitlySafe = false;
        authorityError = error.message;
      }
      removeNotice(`job:${job.jobId}`);
    }

    if (explicitlySafe) {
      const safe = {
        bootId: verifiedLease.authority.boot_id,
        jobId: job.jobId,
        generation: job.acceptedGeneration,
        leaseVerifiedAt: Date.now(),
        name: status.device_name || job.name,
        completedAt: status.updated_at || new Date().toISOString(),
        identity: verifiedLease.identity,
      };
      saveJson(STORAGE_SAFE, safe);
      showSafeNotice(safe);
      const safeModal = showModal({
        title: `${safe.name || 'USB device'} is safe to unplug`,
        message: 'USB Guardian verified logical removal and shfs health. You can now physically unplug the device.',
        actions: [{ label: 'Close', primary: true }],
      });
      safeModal.dataset.guardianSafeApproval = 'true';
      window.setTimeout(() => refreshDevices(true), 500);
      return;
    }

    const reasons = Array.isArray(status.reasons) ? status.reasons : [];
    const failureMessage = coreReportedSafe && !status.authorityVerified
      ? 'The completed result could not be verified as the latest server-authorized operation.'
      : (authorityError || statusMessage(status));
    setNotice(`failed:${job.jobId}`, {
      kind: 'error',
      title: `Safe eject failed for ${job.name}`,
      message: `${failureMessage} The device is not safe to unplug.`,
      dismissible: true,
      action: reasons.length
        ? { label: 'View reason', handler: () => showModal({ title: `Cannot safely eject ${job.name}`, reasons, actions: [{ label: 'Check again', icon: 'fa-refresh', primary: true, handler: () => refreshDevices(true) }, { label: 'Close' }] }) }
        : { label: 'Check again', handler: () => refreshDevices(true) },
    });
    window.setTimeout(() => refreshDevices(true), 500);
  }

  function showSafeNotice(safe) {
    if (!Number.isFinite(safe?.leaseVerifiedAt) || Date.now() - safe.leaseVerifiedAt >= SAFE_LEASE_MS) {
      revokeSafeApproval(
        'Safe-to-unplug approval lease expired',
        'The server lease was not renewed within five seconds.',
        'safe-lease-expired',
      );
      return;
    }
    setNotice('safe', {
      kind: 'success',
      title: `${safe.name || 'USB device'} is safe to unplug`,
      message: 'USB Guardian verified logical removal and shfs health. You can now physically unplug the device.',
      dismissible: true,
    });
    scheduleSafeWatchdog();
  }

  function scheduleSafeWatchdog(delay = SAFE_WATCHDOG_MS) {
    stopSafeWatchdog();
    const safe = loadJson(STORAGE_SAFE, null);
    if (!safe) {
      clearSafeApprovalVisuals();
      return;
    }
    const remaining = safe.leaseVerifiedAt + SAFE_LEASE_MS - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      revokeSafeApproval(
        'Safe-to-unplug approval lease expired',
        'The server lease was not renewed within five seconds.',
        'safe-lease-expired',
      );
      return;
    }
    state.leaseExpiryTimer = window.setTimeout(() => {
      state.leaseExpiryTimer = 0;
      const current = loadJson(STORAGE_SAFE, null);
      if (!current) {
        clearSafeApprovalVisuals();
        return;
      }
      if (Date.now() - current.leaseVerifiedAt >= SAFE_LEASE_MS) {
        revokeSafeApproval(
          'Safe-to-unplug approval lease expired',
          'The server lease was not renewed within five seconds.',
          'safe-lease-expired',
        );
      }
    }, remaining);
    state.watchdogTimer = window.setTimeout(() => {
      state.watchdogTimer = 0;
      verifySafeLease();
    }, Math.max(0, delay));
  }

  async function verifySafeLease() {
    const safe = loadJson(STORAGE_SAFE, null);
    if (!safe) {
      clearSafeApprovalVisuals();
      return;
    }
    if (state.watchdogRequest) {
      return state.watchdogRequest;
    }
    const age = Date.now() - safe.leaseVerifiedAt;
    if (!Number.isFinite(safe.leaseVerifiedAt) || !Number.isFinite(age) || age >= SAFE_LEASE_MS) {
      revokeSafeApproval(
        'Safe-to-unplug approval lease expired',
        'The server lease was not renewed within five seconds.',
        'safe-lease-expired',
      );
      return;
    }
    if (age < SAFE_WATCHDOG_MS) {
      if (!state.watchdogTimer) {
        scheduleSafeWatchdog(SAFE_WATCHDOG_MS - age);
      }
      return;
    }
    window.clearTimeout(state.watchdogTimer);
    state.watchdogTimer = 0;
    state.watchdogRequest = (async () => {
      try {
        const currentLease = loadJson(STORAGE_SAFE, null);
        if (!currentLease) {
          clearSafeApprovalVisuals();
          return;
        }
        if (Date.now() - currentLease.leaseVerifiedAt >= SAFE_LEASE_MS) {
          revokeSafeApproval(
            'Safe-to-unplug approval lease expired',
            'The server lease was not renewed within five seconds.',
            'safe-lease-expired',
          );
          return;
        }
        await verifyServerLeaseSnapshot(currentLease.jobId, currentLease.generation, currentLease.identity);
        const currentSafe = loadJson(STORAGE_SAFE, null);
        if (!currentSafe) {
          clearSafeApprovalVisuals();
          return;
        }
        if (!authorityMatchesSafe(state.authority, currentSafe)) {
          revokeSafeApproval(
            'Safe-to-unplug approval is no longer current',
            'The stored approval no longer matches the verified server authority.',
            'safe-authority-revoked',
          );
          return;
        }
        currentSafe.leaseVerifiedAt = Date.now();
        saveJson(STORAGE_SAFE, currentSafe);
      } catch (error) {
        revokeSafeApproval(
          'Safe-to-unplug approval could not be verified',
          `${error.message} The server lease check failed.`,
          'safe-watchdog-error',
        );
        applyAuthority(null);
      }
    })();
    try {
      await state.watchdogRequest;
    } finally {
      state.watchdogRequest = null;
      if (loadJson(STORAGE_SAFE, null)) {
        scheduleSafeWatchdog();
      } else {
        clearSafeApprovalVisuals();
      }
    }
  }

  async function pollJob(job) {
    if (!state.jobs.has(job.jobId)) {
      return;
    }
    try {
      const status = await api('status', { job_id: job.jobId });
      job.failures = 0;
      const authority = authorityFromPayload(status);
      applyAuthority(authority);
      status.authorityVerified = Boolean(authority
        && status.is_latest_job === true
        && authority.job_id === job.jobId
        && authority.generation === job.acceptedGeneration
        && state.authority?.job_id === authority.job_id
        && state.authority?.generation === authority.generation);
      if (status.boot_id && job.bootId && status.boot_id !== job.bootId) {
        await finishJob(job, { state: 'recovered', message: 'The server rebooted before this operation could be verified.', safe_to_unplug: false });
        return;
      }
      const stateName = String(status.state || '').toLowerCase();
      if (TERMINAL_STATES.has(stateName) || status.terminal === true) {
        await finishJob(job, status);
        return;
      }
      setNotice(`job:${job.jobId}`, {
        kind: 'progress',
        title: `Safely ejecting ${job.name}`,
        message: statusMessage(status),
      });
      syncControls();
      window.setTimeout(() => pollJob(job), POLL_INTERVAL_MS);
    } catch (error) {
      job.failures = (job.failures || 0) + 1;
      setNotice(`job:${job.jobId}`, {
        kind: 'error',
        title: `Cannot verify safe-eject status for ${job.name}`,
        message: `${error.message} Do not unplug the device. Status checking will continue.`,
      });
      window.setTimeout(() => pollJob(job), Math.min(10000, POLL_INTERVAL_MS * Math.max(2, job.failures)));
    }
  }

  async function restoreJobs() {
    const localJobs = loadJson(STORAGE_ACTIVE, []);
    if (Array.isArray(localJobs)) {
      localJobs.forEach((job) => {
        if (job && typeof job.jobId === 'string') {
          state.jobs.set(job.jobId, { ...job, failures: 0 });
        }
      });
    }
    try {
      const server = await api('jobs');
      const serverBootId = typeof server.boot_id === 'string' ? server.boot_id : '';
      const dismissedValue = loadJson(STORAGE_DISMISSED, []);
      const dismissed = new Set(Array.isArray(dismissedValue) ? dismissedValue : []);
      const recentJobs = Array.isArray(server.jobs) ? server.jobs : [];
      const authority = authorityFromPayload(server);
      const authorityJob = authority
        ? recentJobs.find((job) => job?.job_id === authority.job_id)
        : null;
      let latestIsSafe = Boolean(authority
        && authority.boot_id === serverBootId
        && (!state.bootId || state.bootId === serverBootId)
        && authorityJob
        && authorityJob.is_latest_job === true
        && authorityJob.generation === authority.generation
        && String(authorityJob.state || '').toLowerCase() === 'completed'
        && authorityJob.safe_to_unplug === true
        && !state.devices.some((device) => samePhysicalDevice(deviceIdentity(authorityJob.device), device))
        && !dismissed.has(authority.job_id));
      applyAuthority(authority?.boot_id === serverBootId ? authority : null);
      let restoredLease = null;
      if (latestIsSafe) {
        try {
          restoredLease = await verifyServerLeaseSnapshot(
            authority.job_id,
            authority.generation,
            deviceIdentity(authorityJob.device),
          );
        } catch (error) {
          latestIsSafe = false;
          revokeSafeApproval(
            'Stored safe-to-unplug approval could not be renewed',
            error.message,
            'safe-restore-lease-error',
          );
        }
      }
      const storedSafe = loadJson(STORAGE_SAFE, null);
      if (storedSafe && (!latestIsSafe
        || !authorityMatchesSafe(authority, storedSafe))) {
        revokeSafeApproval(
          'Stored safe-to-unplug approval is no longer authoritative',
          'The server does not confirm it as the current authority generation.',
          'safe-restore-revoked',
        );
      }
      const verifiedStoredSafe = loadJson(STORAGE_SAFE, null);
      if (verifiedStoredSafe && latestIsSafe && authorityMatchesSafe(authority, verifiedStoredSafe)) {
        verifiedStoredSafe.leaseVerifiedAt = Date.now();
        verifiedStoredSafe.identity = restoredLease.identity;
        saveJson(STORAGE_SAFE, verifiedStoredSafe);
        showSafeNotice(verifiedStoredSafe);
      } else if (verifiedStoredSafe === null && latestIsSafe) {
        const safe = {
          bootId: serverBootId,
          jobId: authority.job_id,
          generation: authority.generation,
          leaseVerifiedAt: Date.now(),
          name: deviceName(authorityJob.device || {}),
          completedAt: authorityJob.updated_at || new Date().toISOString(),
          identity: restoredLease.identity,
        };
        saveJson(STORAGE_SAFE, safe);
        showSafeNotice(safe);
      }
      for (const status of recentJobs) {
        const jobId = typeof status.job_id === 'string' ? status.job_id : '';
        const stateName = String(status.state || '').toLowerCase();
        if (!jobId || TERMINAL_STATES.has(stateName) || status.terminal === true) {
          continue;
        }
        if (!state.jobs.has(jobId)) {
          state.jobs.set(jobId, {
            jobId,
            bootId: status.boot_id || serverBootId,
            name: status.device_name || 'USB device',
            deviceKeys: deviceKeys(status.device || {}),
            identity: deviceIdentity(status.device),
            acceptedGeneration: authority
              && status.is_latest_job === true
              && status.job_id === authority.job_id
              && status.generation === authority.generation
              ? authority.generation
              : 0,
            failures: 0,
          });
        }
      }
      if (!state.bootId) {
        state.bootId = serverBootId;
      }
    } catch (error) {
      revokeSafeApproval(
        'Safe-to-unplug approval could not be restored',
        `${error.message} The latest server authority could not be verified.`,
        'safe-restore-error',
      );
      applyAuthority(null);
    }
    discardStaleLocalState();
    expireSafeNoticeForReturnedDevice();
    persistJobs();
    for (const job of state.jobs.values()) {
      pollJob(job);
    }
  }

  function bindControls() {
    const body = document.getElementById('disk-table-body');
    if (!body) return;
    body.addEventListener('click', (event) => {
      const button = event.target?.closest?.('.usb-guardian-control[data-guardian-device]');
      if (!button || !body.contains(button)) return;
      event.preventDefault();
      event.stopPropagation();
      inspectDeviceOnDemand(button.dataset.guardianDevice || '', button.dataset.guardianName || 'USB device');
    });
  }

  function startAuthorityStorageListener() {
    window.addEventListener('storage', (event) => {
      if (event.key === null) {
        const hadSafeVisuals = state.notices.has('safe')
          || document.getElementById('usb-guardian-modal-layer')?.dataset.guardianSafeApproval === 'true';
        clearSafeApprovalVisuals();
        applyAuthority(null, false);
        if (hadSafeVisuals) {
          setNotice('safe-storage-revoked', {
            kind: 'warning',
            title: 'Safe-to-unplug approval was revoked in another page',
            message: 'Run safe eject again and wait for a new verified approval. Do not unplug the device.',
            dismissible: true,
          });
        }
        return;
      }
      if (event.key === STORAGE_SAFE) {
        let newSafe = null;
        try {
          newSafe = event.newValue ? JSON.parse(event.newValue) : null;
        } catch (_error) {
          newSafe = null;
        }
        if (!newSafe || !authorityMatchesSafe(state.authority, newSafe)) {
          const hadSafeVisuals = state.notices.has('safe')
            || document.getElementById('usb-guardian-modal-layer')?.dataset.guardianSafeApproval === 'true';
          clearSafeApprovalVisuals();
          if (!hadSafeVisuals) {
            return;
          }
          setNotice('safe-storage-revoked', {
            kind: 'warning',
            title: 'Safe-to-unplug approval was revoked in another page',
            message: 'Run safe eject again and wait for a new verified approval. Do not unplug the device.',
            dismissible: true,
          });
        }
        return;
      }
      if (event.key !== STORAGE_AUTHORITY) {
        return;
      }
      let authority = null;
      try {
        authority = parseAuthority(event.newValue ? JSON.parse(event.newValue) : null);
      } catch (_error) {
        authority = null;
      }
      applyAuthority(authority, false);
    });
  }

  function verifySafeLeaseOnResume() {
    const safe = loadJson(STORAGE_SAFE, null);
    if (!safe) {
      clearSafeApprovalVisuals();
      return;
    }
    const age = Date.now() - safe.leaseVerifiedAt;
    if (!Number.isFinite(safe.leaseVerifiedAt) || !Number.isFinite(age) || age >= SAFE_LEASE_MS) {
      revokeSafeApproval(
        'Safe-to-unplug approval lease expired while the page was inactive',
        'The five-second server lease elapsed before this page resumed.',
        'safe-resume-expired',
      );
      return;
    }
    if (state.watchdogRequest) {
      return;
    }
    if (age < SAFE_WATCHDOG_MS) {
      if (!state.watchdogTimer) {
        scheduleSafeWatchdog(SAFE_WATCHDOG_MS - age);
      }
      return;
    }
    verifySafeLease();
  }

  function startSafeLeaseResumeListeners() {
    window.addEventListener('focus', verifySafeLeaseOnResume);
    window.addEventListener('pageshow', verifySafeLeaseOnResume);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        verifySafeLeaseOnResume();
      }
    });
  }

  async function initialize() {
    startAuthorityStorageListener();
    startSafeLeaseResumeListeners();
    bindControls();
    await restoreJobs();
    syncControls();
  }

  window.UDSafeEject = Object.freeze({ refreshControls: syncControls });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize, { once: true });
  } else {
    initialize();
  }
})();
