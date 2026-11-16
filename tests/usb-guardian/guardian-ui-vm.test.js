'use strict';

const fs = require('fs');
const vm = require('vm');

const guardianPath = 'source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/assets/guardian.js';
const original = fs.readFileSync(guardianPath, 'utf8');

const initializeSource = original.slice(original.indexOf('async function initialize()'));
assert(!initializeSource.slice(0, initializeSource.indexOf("if (document.readyState")).includes('refreshDevices('),
  'initialization must not perform an eligibility list request before a static control is clicked');
assert(!original.includes('MutationObserver') && !original.includes('createUDRendererBridge')
  && !original.includes('decorateDiskRows'), 'native UI must not inject controls or wrap UD rendering');
assert(!original.includes("getAttribute('role') !== 'umount'"),
  'static controls must not disappear because UD represents mounted/running aggregate disks with another role');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function response(data, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => data };
}

function createHarness(handler, initial = {}, fastLease = false, i18n = {}) {
  const values = new Map(Object.entries(initial).map(([key, value]) => [key, JSON.stringify(value)]));
  const localStorage = {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    clear: () => values.clear(),
  };
  let source = original;
  if (fastLease) {
    source = source
      .replace('const SAFE_WATCHDOG_MS = 2000;', 'const SAFE_WATCHDOG_MS = 20;')
      .replace('const SAFE_LEASE_MS = 5000;', 'const SAFE_LEASE_MS = 50;')
      .replace('const SAFE_REQUEST_TIMEOUT_MS = 1500;', 'const SAFE_REQUEST_TIMEOUT_MS = 200;');
  }
  source = source.replace(/\}\)\(\);\s*$/, `globalThis.__guardianTest = {
    applyAuthority, controlSignature, syncControls, dismissSafeApproval, finishJob, parseAuthority, refreshDevices,
    reasonParts, restoreJobs, showSafeNotice, startAuthorityStorageListener,
    startSafeLeaseResumeListeners, state, stopSafeWatchdog, verifySafeLease,
    verifyServerLeaseSnapshot, tr, STORAGE_SAFE, STORAGE_AUTHORITY
  };\n})();`);
  const windowListeners = new Map();
  const documentListeners = new Map();
  const elements = new Map();
  const addListener = (listeners, name, listener) => {
    const registered = listeners.get(name) || [];
    registered.push(listener);
    listeners.set(name, registered);
  };
  const dispatch = (listeners, name, event = {}) => {
    for (const listener of listeners.get(name) || []) {
      listener(event);
    }
  };
  const context = {
    AbortController,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    Date,
    window: {
      UsbGuardianRuntime: { apiUrl: '/plugins/unassigned.devices/usb-guardian/api.php', csrfToken: 'test', i18n },
      localStorage,
      setTimeout,
      clearTimeout,
      addEventListener: (name, listener) => addListener(windowListeners, name, listener),
      fetch: async (_url, options) => {
        const fields = new URLSearchParams(options.body);
        return handler(fields.get('action'), fields, options.signal);
      },
    },
    document: {
      readyState: 'loading',
      visibilityState: 'visible',
      addEventListener: (name, listener) => addListener(documentListeners, name, listener),
      getElementById: (id) => elements.get(id) || null,
      querySelectorAll: () => [],
    },
  };
  context.globalThis = context;
  vm.runInNewContext(source, context, { filename: guardianPath });
  return {
    test: context.__guardianTest,
    values,
    localStorage,
    elements,
    dispatchWindow: (name, event) => dispatch(windowListeners, name, event),
    dispatchDocument: (name, event) => dispatch(documentListeners, name, event),
    document: context.document,
  };
}

const boot = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const jobA = '11111111-1111-4111-8111-111111111111';
const jobB = '22222222-2222-4222-8222-222222222222';
const authorityA = { schema_version: 1, boot_id: boot, job_id: jobA, generation: 1 };
const authorityB = { schema_version: 1, boot_id: boot, job_id: jobB, generation: 2 };
const deviceA = {
  kernel_name: 'sdb', usb_path: 'devices/pci0000:00/usb1/1-2', usb_vid: '0781', usb_pid: '5581',
  serial: 'A', usb_serial: 'USB-A', vendor: 'Fixture', model: 'A',
};

function completedJobsPayload() {
  return {
    boot_id: boot,
    jobs: [{
      job_id: jobA,
      state: 'completed',
      terminal: true,
      safe_to_unplug: true,
      generation: 1,
      is_latest_job: true,
      device: deviceA,
    }],
    authority: authorityA,
    generation: 1,
    is_latest_job: true,
  };
}

function completedLeasePayload() {
  return {
    boot_id: boot,
    authority: authorityA,
    generation: 1,
    is_latest_job: true,
    job: { job_id: jobA, state: 'completed', terminal: true, safe_to_unplug: true },
    device_absent: true,
    identity: {
      usb_path: deviceA.usb_path,
      usb_vid: deviceA.usb_vid,
      usb_pid: deviceA.usb_pid,
      usb_serial: deviceA.usb_serial,
    },
  };
}

async function main() {
  {
    const harness = createHarness(async () => { throw new Error('no eligibility request while rendering'); });
    const makeButton = () => {
      const status = { textContent: '' };
      const icon = { className: '' };
      const attributes = {};
      return {
        dataset: { guardianDevice: 'sdb', guardianName: 'USB & backup' },
        parentElement: { querySelector: () => status },
        classList: { toggle: (name, enabled) => { attributes[name] = enabled; } },
        setAttribute: (name, value) => { attributes[name] = value; },
        querySelector: () => icon, status, icon, attributes,
      };
    };
    let button = makeButton();
    harness.document.querySelectorAll = () => [button];
    harness.test.syncControls();
    assert(button.title === 'Safely eject USB & backup', 'native identity must label the button without parsing a row');
    harness.test.state.checkingKeys.add('sdb');
    harness.test.syncControls();
    assert(button.disabled && button.status.textContent === 'Checking USB & backup', 'inspection must update the existing button');
    button = makeButton();
    harness.test.syncControls();
    assert(button.disabled, 'new server-rendered rows must immediately regain active operation status');
    harness.test.state.enabled = false;
    harness.test.syncControls();
    assert(button.hidden, 'disabling the feature must hide native controls');
  }

  {
    let fail = false;
    const listedDevice = { ...deviceA, target: 'signed-target', eligible: true, reasons: [] };
    const harness = createHarness(async (action) => {
      if (action !== 'list') throw new Error(`unexpected ${action}`);
      if (fail) return response({ ok: false, error: { message: 'temporary list failure' } }, 503);
      return response({ ok: true, data: { meta: { boot_id: boot }, devices: [listedDevice] } });
    });
    await harness.test.refreshDevices(true);
    const firstSignature = harness.test.controlSignature('sdb');
    await harness.test.refreshDevices(true);
    assert(harness.test.controlSignature('sdb') === firstSignature,
      'an unchanged list refresh must preserve the control signature');
    fail = true;
    await harness.test.refreshDevices(true);
    assert(harness.test.state.devices.length === 1,
      'a temporary list failure must retain the last verified device row mapping');
    assert(harness.test.state.listError === 'temporary list failure',
      'a temporary list failure must retain its explanation for the click-result dialog');
    assert(harness.test.controlSignature('sdb') === firstSignature,
      'a temporary list failure must not change or replace the static control');
  }

  {
    const sameTime = '2026-07-16T00:00:00Z';
    const jobs = [
      { job_id: jobA, state: 'completed', terminal: true, safe_to_unplug: true, updated_at: sameTime, device: deviceA, generation: 2, is_latest_job: false },
      { job_id: jobB, state: 'failed', terminal: true, safe_to_unplug: false, updated_at: sameTime, generation: 2, is_latest_job: true },
    ];
    const initialSafe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    const harness = createHarness(async (action) => {
      if (action === 'jobs') return response({ ok: true, data: { boot_id: boot, jobs, authority: authorityB, generation: 2, is_latest_job: true } });
      throw new Error(`unexpected ${action}`);
    }, {
      'usb.guardian.safe.v1': initialSafe,
      'usb.guardian.authority.v1': authorityA,
    });
    harness.test.state.bootId = boot;
    await harness.test.restoreJobs();
    assert(!harness.values.has('usb.guardian.safe.v1'), 'B failed must revoke A safe approval');
    assert(harness.test.state.authority.job_id === jobB, 'authority, not same-second array order, must select B');
    const staleJob = { jobId: jobA, bootId: boot, name: 'A', identity: deviceA, acceptedGeneration: 1 };
    harness.test.state.jobs.set(jobA, staleJob);
    await harness.test.finishJob(staleJob, {
      state: 'completed', terminal: true, safe_to_unplug: true,
      authorityVerified: false, device: deviceA,
    });
    assert(!harness.values.has('usb.guardian.safe.v1'), 'A completion after B authority must not recreate green approval');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    let leaseRequests = 0;
    const harness = createHarness(async (action) => {
      if (action === 'lease') {
        leaseRequests += 1;
        return response({ ok: true, data: completedLeasePayload() });
      }
      throw new Error(`unexpected ${action}`);
    }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    }, true);
    harness.test.state.authority = authorityA;
    harness.test.showSafeNotice(safe);
    let modalClosed = false;
    harness.elements.set('usb-guardian-modal-layer', {
      dataset: { guardianSafeApproval: 'true' },
      remove: () => {
        modalClosed = true;
        harness.elements.delete('usb-guardian-modal-layer');
      },
    });
    harness.localStorage.removeItem('usb.guardian.safe.v1');
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert(!harness.test.state.notices.has('safe'), 'timer-only safe removal must clear the green banner');
    assert(modalClosed, 'timer-only safe removal must close the green modal');
    assert(harness.test.state.watchdogTimer === 0 && harness.test.state.leaseExpiryTimer === 0,
      'timer-only safe removal must stop all lease timers');
    assert(leaseRequests === 0, 'timer-only safe removal must not make another lease request');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    let available = false;
    let leaseRequests = 0;
    const harness = createHarness(async (action) => {
      if (action === 'list' && !available) return response({ ok: false, error: { message: 'list unavailable' } }, 503);
      if (action === 'list') return response({ ok: true, data: { meta: { boot_id: boot }, devices: [] } });
      if (action === 'jobs') return response({ ok: true, data: completedJobsPayload() });
      if (action === 'lease') {
        leaseRequests += 1;
        return response({ ok: true, data: completedLeasePayload() });
      }
      throw new Error(`unexpected ${action}`);
    }, { 'usb.guardian.safe.v1': safe });
    await harness.test.refreshDevices(true);
    assert(!harness.values.has('usb.guardian.safe.v1'), 'list error must revoke safe approval immediately');
    assert(!harness.values.has('usb.guardian.dismissed.v1'), 'automatic list failure must not dismiss the safe job');
    available = true;
    await harness.test.refreshDevices(true);
    await harness.test.restoreJobs();
    assert(harness.values.has('usb.guardian.safe.v1'), 'safe approval must be recoverable after a temporary list failure');
    assert(leaseRequests === 1, 'jobs discovery alone must not restore a green approval without a lease');
    harness.test.stopSafeWatchdog();
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    const harness = createHarness((action, _fields, signal) => {
      if (action !== 'lease') throw new Error(`unexpected ${action}`);
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
      });
    }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    }, true);
    harness.test.state.authority = authorityA;
    harness.test.showSafeNotice(safe);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert(!harness.values.has('usb.guardian.safe.v1'), 'independent lease timer must revoke while fetch is hung');
    await new Promise((resolve) => setTimeout(resolve, 150));
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now() - 25, identity: deviceA };
    const harness = createHarness(async (action) => {
      if (action === 'lease') {
        return response({
          ok: false,
          error: { message: 'The completed USB device has no serial number and a matching VID/PID is present.' },
        }, 409);
      }
      throw new Error(`unexpected ${action}`);
    }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    }, true);
    harness.test.state.authority = authorityA;
    await harness.test.verifySafeLease();
    const warning = harness.test.state.notices.get('safe-watchdog-error');
    assert(warning?.message.includes('has no serial number'), 'lease failure must preserve the specific fail-closed reason');
    assert(!harness.values.has('usb.guardian.dismissed.v1'), 'lease failure must not dismiss the safe job');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    let leaseRequests = 0;
    const harness = createHarness(async (action, fields) => {
      if (action === 'lease') {
        leaseRequests += 1;
        assert(fields.get('job_id') === jobA, 'lease request must carry the exact job id');
        assert(fields.get('generation') === '1', 'lease request must carry the exact generation');
        return response({ ok: true, data: completedLeasePayload() });
      }
      throw new Error(`unexpected ${action}`);
    }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    }, true);
    harness.test.state.authority = authorityA;
    harness.test.showSafeNotice(safe);
    harness.test.startSafeLeaseResumeListeners();

    for (let index = 0; index < 20; index += 1) {
      harness.dispatchWindow(index % 2 ? 'focus' : 'pageshow');
      harness.dispatchDocument('visibilitychange');
      await harness.test.verifySafeLease();
      await new Promise((resolve) => setImmediate(resolve));
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
    harness.test.stopSafeWatchdog();

    assert(leaseRequests >= 1 && leaseRequests <= 2, `resume storm made ${leaseRequests} lease requests`);
  }

  {
    const harness = createHarness(async (action) => {
      if (action === 'lease') return response({ ok: true, data: completedLeasePayload() });
      throw new Error(`unexpected ${action}`);
    });
    const verified = await harness.test.verifyServerLeaseSnapshot(jobA, 1, deviceA);
    assert(verified.authority.job_id === jobA, 'lease response must verify authority');
    assert(verified.identity.usb_serial === deviceA.usb_serial, 'lease response must verify USB identity');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    const harness = createHarness(async () => { throw new Error('no API request expected'); }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    });
    harness.test.state.authority = authorityA;
    harness.test.showSafeNotice(safe);
    harness.test.startSafeLeaseResumeListeners();
    let modalClosed = false;
    harness.elements.set('usb-guardian-modal-layer', {
      dataset: { guardianSafeApproval: 'true' },
      remove: () => {
        modalClosed = true;
        harness.elements.delete('usb-guardian-modal-layer');
      },
    });
    harness.localStorage.removeItem('usb.guardian.safe.v1');
    harness.dispatchWindow('pageshow');
    assert(!harness.test.state.notices.has('safe'), 'bfcache resume without storage must remove the green banner');
    assert(modalClosed, 'bfcache resume without storage must close the green modal');
    assert(harness.test.state.watchdogTimer === 0, 'bfcache resume without storage must stop the watchdog');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    const harness = createHarness(async () => { throw new Error('no API request expected'); }, {
      'usb.guardian.safe.v1': safe,
      'usb.guardian.authority.v1': authorityA,
    });
    harness.test.state.authority = authorityA;
    harness.test.showSafeNotice(safe);
    harness.test.startAuthorityStorageListener();
    let modalClosed = false;
    let controlsRefreshed = false;
    harness.elements.set('usb-guardian-modal-layer', {
      dataset: { guardianSafeApproval: 'true' },
      remove: () => {
        modalClosed = true;
        harness.elements.delete('usb-guardian-modal-layer');
      },
    });
    harness.document.querySelectorAll = () => { controlsRefreshed = true; return []; };
    harness.localStorage.clear();
    harness.dispatchWindow('storage', { key: null, newValue: null });
    assert(!harness.test.state.notices.has('safe'), 'cross-tab storage clear must remove the green banner');
    assert(modalClosed, 'cross-tab storage clear must close the green safe modal');
    assert(controlsRefreshed, 'cross-tab storage clear must refresh device controls');
    assert(harness.test.state.watchdogTimer === 0, 'cross-tab storage clear must stop the watchdog');
    assert(harness.test.state.authority === null, 'cross-tab storage clear must revoke in-memory authority');
    assert(!harness.values.has('usb.guardian.dismissed.v1'), 'cross-tab storage clear must not create a local tombstone');
  }

  {
    const safe = { bootId: boot, jobId: jobA, generation: 1, leaseVerifiedAt: Date.now(), identity: deviceA };
    const harness = createHarness(async () => { throw new Error('no API request expected'); }, {
      'usb.guardian.safe.v1': safe,
    });
    harness.test.dismissSafeApproval();
    const dismissed = JSON.parse(harness.values.get('usb.guardian.dismissed.v1'));
    assert(dismissed.includes(jobA), 'explicit user dismissal must create a tombstone');
  }

  {
    const zh = JSON.parse(fs.readFileSync('source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices/usb-guardian/language/zh_CN.json', 'utf8'));
    const harness = createHarness(async () => { throw new Error('no API request expected'); }, {}, false, zh);
    assert(harness.test.tr('Safely eject Fixture A') === '安全弹出 Fixture A',
      'Chinese template translation must preserve the dynamic device name');
    assert(harness.test.tr('validating stable device identity') === '正在验证稳定的设备身份',
      'Chinese progress messages must be translated');
    const reason = harness.test.reasonParts({
      code: 'inspection_failed',
      message: 'a future backend inspection failure',
      detail: 'pid=123 path=/mnt/disks/fixture',
      advice: 'a future backend recovery instruction',
    });
    assert(reason.message === '无法完整验证设备的安全状态',
      'Unknown backend reason wording must use the localized reason-code fallback');
    assert(reason.advice.includes('保持设备连接'),
      'Reason-code fallback must include a localized action suggestion');
    assert(reason.detail === 'pid=123 path=/mnt/disks/fixture',
      'Diagnostic identifiers and paths must remain unchanged');
  }

  console.log('guardian UI authority and lease VM tests passed.');
}

main().catch((error) => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
