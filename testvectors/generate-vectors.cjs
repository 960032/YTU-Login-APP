'use strict';
/*
 * generate-vectors.cjs —— 生成 SrunCrypto 的等价性测试向量。
 * 全部向量由 **Node 参考实现** artifacts/srun-impl/srun-crypto.js 现算产出，Kotlin 侧逐字符比对。
 * 安全约束：只使用合成数据；不读取任何真实凭据文件；不出现任何真实凭据。
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const SRC = path.resolve(__dirname, '..', '..', 'srun-impl', 'srun-crypto.js');
const OUT = path.resolve(__dirname, 'vectors.json');
const EXPECT_SHA = '1A56E0EA990F98E6D2A7E0F4A914FCBCEED86B7A52B0F6094EF076FEFD424FE6';

const srcBytes = fs.readFileSync(SRC);
const srcSha = crypto.createHash('sha256').update(srcBytes).digest('hex').toUpperCase();
if (srcSha !== EXPECT_SHA) {
  console.error('FATAL: 参考实现 sha256 与基准不一致，向量不可信');
  console.error('  expected = ' + EXPECT_SHA);
  console.error('  actual   = ' + srcSha);
  process.exit(3);
}
const srun = require(SRC);

/* ===== 合成数据（严禁真实凭据） ===== */
const USER = '202000000000@ytu';
const PWD = 'TestPassword123';
const TOKEN = '3a5f9b2c1d8e4f7a';
const LONG_TOKEN = 't0k3n'.repeat(24);            // 120 字符
const IP = '10.10.20.30';
const AC_ID = '5';                                 // 注意：字符串形态（Kotlin API 冻结为 String）
const CN_USER = '张三@移动';
const CN_PWD = '密码-测试-2024';

const longStr = '长'.repeat(400) + 'x'.repeat(700); // 1100 字符
const byteFull = String.fromCharCode.apply(null, Array.from({ length: 256 }, (_, i) => i));

const textCases = ['', 'abc', '你好，世界', 'emoji😀🚀测试', 'nul\u0000char', longStr];

const hmacCases = [
  ['', 'TestPassword123'],
  ['', ''],
  ['onlykey', 'TestPassword123'],
  [TOKEN, PWD],
  [TOKEN, ''],
  [TOKEN, CN_PWD],
  [LONG_TOKEN, 'long-message-' + 'm'.repeat(600)],
  ['', '中文消息'],
  [TOKEN, 'unicode:😀🧪\u0000end'],
];

const b64Ok = ['', 'A', 'AB', 'ABC', 'abcd', 'abc123', 'abc+/=', '\u0000', byteFull, byteFull.slice(0, 255), 'x'.repeat(1000)];
const b64Err = ['\u0100', '你好', '😀', 'ab\u0100'];
const b64ErrCases = [];
for (const s of b64Err) {
  let msg = null;
  try { srun.base64Encode(s); } catch (e) { msg = String((e && e.message) || e); }
  if (!msg) { console.error('FATAL: 参考实现对 ' + JSON.stringify(s) + ' 未抛错，向量不可信'); process.exit(4); }
  console.log('自检: 参考实现 base64Encode(' + JSON.stringify(s) + ') 抛出 -> ' + msg);
  b64ErrCases.push({ input: s, expectError: true, errorMessage: msg });
}

const pwdCases = [
  [PWD, TOKEN],
  ['', ''],
  [CN_PWD, TOKEN],
  [PWD, LONG_TOKEN],
  [PWD, ''],
  ['密码with emoji😀', TOKEN],
];

const infoCases = [
  [USER, PWD, IP, AC_ID, TOKEN],
  [USER, PWD, IP, AC_ID, ''],
  [CN_USER, CN_PWD, IP, AC_ID, TOKEN],
  [USER, PWD, '192.168.1.100', '5', LONG_TOKEN],
  [USER, PWD, '2001:db8::1', '5', TOKEN],
];

function chk(token, username, plainPwd, acId, ip, n, type) {
  const hmd5 = srun.hmacMd5(token, plainPwd);
  const info = srun.infoField(username, plainPwd, ip, acId, token);
  return { token, username, hmd5, acId, ip, n, type, info, expected: srun.chksum(token, username, hmd5, acId, ip, n, type, info) };
}

const chksumCases = [
  chk(TOKEN, USER, PWD, AC_ID, IP, 200, 1),
  chk('', USER, PWD, AC_ID, IP, 200, 1),
  chk(TOKEN, CN_USER, CN_PWD, AC_ID, IP, 200, 1),
  chk(LONG_TOKEN, USER, PWD, AC_ID, IP, 300, 2),
  chk(TOKEN, USER, PWD, AC_ID, '2001:db8::1', 200, 1),
];

const vectors = {
  meta: {
    generator: 'artifacts/android-app/testvectors/generate-vectors.cjs',
    generatedAt: new Date().toISOString(),
    node: process.version,
    reference: { path: 'artifacts/srun-impl/srun-crypto.js', sha256: srcSha, bytes: srcBytes.length },
    note: '全部向量由 Node 参考实现现算；只用合成账号，不含任何真实凭据。',
    syntheticInputs: { username: USER, password: PWD, token: TOKEN, longTokenChars: LONG_TOKEN.length, ip: IP, acId: AC_ID },
  },
  md5: textCases.map((s) => ({ input: s, expected: srun.md5(s) })),
  sha1: textCases.map((s) => ({ input: s, expected: srun.sha1(s) })),
  hmacMd5: hmacCases.map(([key, msg]) => ({ key, msg, expected: srun.hmacMd5(key, msg) })),
  base64Encode: b64Ok.map((s) => ({ input: s, expected: srun.base64Encode(s) })).concat(b64ErrCases),
  passwordField: pwdCases.map(([plainPwd, token]) => ({ plainPwd, token, expected: srun.passwordField(plainPwd, token) })),
  chksum: chksumCases,
  infoField: infoCases.map(([username, plainPwd, ip, acId, token]) => ({ username, plainPwd, ip, acId, token, expected: srun.infoField(username, plainPwd, ip, acId, token) })),
};

fs.writeFileSync(OUT, JSON.stringify(vectors, null, 2) + '\n', 'utf8');

console.log('参考实现 sha256 = ' + srcSha + '  （与基准一致）');
console.log('node ' + process.version);
console.log('输出文件 = ' + OUT);
let total = 0;
for (const k of ['md5', 'sha1', 'hmacMd5', 'base64Encode', 'passwordField', 'chksum', 'infoField']) {
  console.log('  ' + k + ': ' + vectors[k].length + ' 条');
  total += vectors[k].length;
}
console.log('总向量条数 = ' + total);
console.log('抽样 md5("") = ' + vectors.md5[0].expected);
console.log('抽样 base64Encode("") = "' + vectors.base64Encode[0].expected + '"');
console.log('抽样 infoField(合成账号) = ' + vectors.infoField[0].expected);
