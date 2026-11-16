// Run with PHP_BIN=/path/to/php node tests/safe-remove-ui.test.js.
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const vm = require('node:vm');
const path = require('node:path');
const plugin = path.resolve(__dirname, '../source/unassigned.devices/usr/local/emhttp/plugins/unassigned.devices');
const render = String.raw`
$catalog = $argv[2] === 'zh_CN' ? parse_ini_file($argv[1].'/language/zh_CN/safe_remove.txt', false, INI_SCANNER_RAW) : [];
function _($text) { global $catalog; return $catalog[str_replace(['?', '.'], '', $text)] ?? $text; }
$var = ['csrf_token' => 'test-token'];
$page = file_get_contents($argv[1].'/DeviceSettings.page');
$start = strpos($page, 'function safe_remove_usb(button)');
$end = strpos($page, '/* Detach a disk device. */', $start);
eval('?>'.substr($page, $start, $end - $start));
`;
let checks = 0;
for (const locale of ['en_US', 'zh_CN']) {
  const php = spawnSync(process.env.PHP_BIN || 'php', ['-d', 'short_open_tag=1', '-r', render, plugin, locale], {encoding: 'utf8'});
  assert.equal(php.status, 0, php.stderr);
  for (const scenario of ['cancel', 'success', 'busy', 'mounted', 'flush', 'detach', 'inspection', 'unknown', 'network']) {
    let status = '', disabled = false, request, confirmation;
    const button = {dataset: {device: '/dev/sdb', serial: 'USB_TEST', sequence: '123'}};
    const $ = target => target === button ? {prop: (name, value) => { disabled = value; }} : {text: value => { status = value; }};
    $.post = (url, payload) => {
      request = payload;
      return {
        done(fn) { if (scenario !== 'network') fn({success: scenario === 'success', reason: scenario}); return this; },
        fail(fn) { if (scenario === 'network') fn(); return this; }
      };
    };
    const context = {window: {confirm: text => { confirmation = text; return scenario !== 'cancel'; }}, $, UDURL: '/native-ud'};
    vm.createContext(context);
    vm.runInContext(php.stdout, context);
    context.safe_remove_usb(button);
    assert.equal(/\p{Script=Han}/u.test(confirmation), locale === 'zh_CN');
    if (scenario === 'cancel') {
      assert.equal(request, undefined);
    } else {
      assert.equal(request.action, 'safe_remove');
      assert.equal(request.sequence, '123');
      assert.equal(request.csrf_token, 'test-token');
      assert.equal(disabled, scenario === 'success');
      assert.equal(/\p{Script=Han}/u.test(status), locale === 'zh_CN');
      assert.ok(status.length > 0);
      if (scenario !== 'success') assert.doesNotMatch(status, /You can unplug|可以拔出/);
    }
    checks++;
  }
}
console.log(`${checks} native button scenarios passed in English and Simplified Chinese`);
