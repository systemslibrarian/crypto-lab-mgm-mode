/**
 * RFC 9058 Appendix A, every value, extracted by scripts/extract-vectors.mjs
 * from the RFC text with sha256 2bc87e4c0078a6807a31307292e9b940092e0ef38e9c3c6c35f5f1ea5f1b312f.
 * Do not edit by hand: regenerate it.
 *
 * Per example: the inputs, then each intermediate value the RFC prints — Y_i,
 * E_K(Y_i), Z_i, H_i, the running sum after every block — and the tag. The
 * tests compare the implementation against ALL of them, so a bug that happens
 * to produce the right tag by accident cannot pass.
 */
export interface MgmVector {
  cipher: 'Magma' | 'Kuznyechik';
  example: number;
  key: string; icn: string; aad: string; plaintext: string;
  y: string[]; keystream: string[]; ciphertext: string;
  z: string[]; h: string[]; runningSum: string[];
  lengthBlock: string; finalSum: string; tag: string;
}

export const RFC9058_SHA256 = '2bc87e4c0078a6807a31307292e9b940092e0ef38e9c3c6c35f5f1ea5f1b312f';

export const RFC9058_VECTORS: MgmVector[] = [
  {
    "cipher": "Kuznyechik",
    "example": 1,
    "key": "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
    "icn": "1122334455667700ffeeddccbbaa9988",
    "aad": "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505",
    "plaintext": "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
    "y": [
      "7f679d90bebc24305a468d42b9d4edcd",
      "7f679d90bebc24305a468d42b9d4edce",
      "7f679d90bebc24305a468d42b9d4edcf",
      "7f679d90bebc24305a468d42b9d4edd0",
      "7f679d90bebc24305a468d42b9d4edd1"
    ],
    "keystream": [
      "b85748c512f31990aa567ef15335db74",
      "8064f0126fac9b2c5b6eac21612f9433",
      "5858821d40c0cd0d0ac1e6c247098f1c",
      "e43f5081b58f0b49012f8ee86acd6dfa",
      "86ce9e2a0a1225e3335691b20d5a3348"
    ],
    "ciphertext": "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552",
    "z": [
      "7fc245a8586e6602a7bbdb2786bdc66f",
      "7fc245a8586e6603a7bbdb2786bdc66f",
      "7fc245a8586e6604a7bbdb2786bdc66f",
      "7fc245a8586e6605a7bbdb2786bdc66f",
      "7fc245a8586e6606a7bbdb2786bdc66f",
      "7fc245a8586e6607a7bbdb2786bdc66f",
      "7fc245a8586e6608a7bbdb2786bdc66f",
      "7fc245a8586e6609a7bbdb2786bdc66f",
      "7fc245a8586e660aa7bbdb2786bdc66f"
    ],
    "h": [
      "8db187d653830ea4bc446476952c300b",
      "7a24f72630e3763721c8f3cdb1da0e31",
      "4411962117d20635c525e0a24db4b90a",
      "d8c9623c4dbfe814ce7c1c0ceaa959db",
      "a5e1f195333e1482969931bfbe6dfd43",
      "b4ca808caccfb3f91724e48a2c7ee9d2",
      "72908fc074e469e8901bd188ea91c331",
      "23ca2715b02c68313bfdacb39e4d0fb8",
      "bcbce6c41aa355a4148862bf64bd830d"
    ],
    "runningSum": [
      "4cf427f4adb75cf4c0da39d5ab48cf38",
      "9495440ef624a1ddc6f5d9772850c573",
      "a49a8cd8a6f27423db79e44ab306d942",
      "09fe3f6a833c21b39027d0206a84e15a",
      "b5da26bb00eba80435d7976bc6b5464d",
      "dd1c0eeef783c8eb2a33f358d7230ee5",
      "896ce10832ebeaf9069f3f7376594d40",
      "991af5c9d080f76387fe649e7c93c642"
    ],
    "lengthBlock": "00000000000001480000000000000218",
    "finalSum": "c0c722db5e0bd6db257673833d567128",
    "tag": "cf5d656f40c34f5c46e8bb0e29fcdb4c"
  },
  {
    "cipher": "Kuznyechik",
    "example": 2,
    "key": "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
    "icn": "1122334455667700ffeeddccbbaa9988",
    "aad": "01010101010101010101010101010101",
    "plaintext": "",
    "y": [],
    "keystream": [],
    "ciphertext": "",
    "z": [
      "7932726896c43e3fbfd65089ebf1e5b6",
      "7932726896c43e40bfd65089ebf1e5b6"
    ],
    "h": [
      "993a8066ccc0a40fac4a14f7a2f66d9b",
      "0c38a71ee793bf768981bfcd7cda78c8"
    ],
    "runningSum": [
      "0ac11e2c1cd607d82fe35554b4010281"
    ],
    "lengthBlock": "00000000000000800000000000000000",
    "finalSum": "ca1ef89271ea60c4539e40eb26c2805d",
    "tag": "7901e9ea2085cd247ed249695f9f8a85"
  },
  {
    "cipher": "Magma",
    "example": 1,
    "key": "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "icn": "12def06b3c130a59",
    "aad": "01010101010101010202020202020202030303030303030304040404040404040505050505050505ea",
    "plaintext": "ffeeddccbbaa998811223344556677008899aabbcceeff0a001122334455667799aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899aabbcc",
    "y": [
      "5623890162de31bf",
      "5623890162de31c0",
      "5623890162de31c1",
      "5623890162de31c2",
      "5623890162de31c3",
      "5623890162de31c4",
      "5623890162de31c5",
      "5623890162de31c6",
      "5623890162de31c7"
    ],
    "keystream": [
      "387bdba0e43439b3",
      "9433000610f7f2ae",
      "97b7aa6d73c58757",
      "9415528bffc9e80a",
      "03f768bff182d670",
      "fd05f84e9b09d2fe",
      "da4d908a95b175c4",
      "65997396dac24bd7",
      "a900504a148dee26"
    ],
    "ciphertext": "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e03bb9c",
    "z": [
      "2b073f0494f372a0",
      "2b073f0594f372a0",
      "2b073f0694f372a0",
      "2b073f0794f372a0",
      "2b073f0894f372a0",
      "2b073f0994f372a0",
      "2b073f0a94f372a0",
      "2b073f0b94f372a0",
      "2b073f0c94f372a0",
      "2b073f0d94f372a0",
      "2b073f0e94f372a0",
      "2b073f0f94f372a0",
      "2b073f1094f372a0",
      "2b073f1194f372a0",
      "2b073f1294f372a0",
      "2b073f1394f372a0"
    ],
    "h": [
      "708a78191cdd22aa",
      "6f02cc464b2fa0a3",
      "9f81f226fd196f05",
      "b9c2ac9be5b5dff9",
      "74b5ec96551bf888",
      "7eb021a4035b04c3",
      "c2a9c3a8704d9bb0",
      "f5d505a87b8383b5",
      "f795e75fdeb8933c",
      "65a1a3e680f08145",
      "1c74a5764cb0d595",
      "dc8447a514e783e7",
      "a7e3afe004ee16e3",
      "a5aabb0b7980d071",
      "6e104cc933525c5d",
      "8311b6024aa966c1"
    ],
    "runningSum": [
      "d6bb5bea81931262",
      "dd1c824e917849a5",
      "05892217f65adac7",
      "d1db9b7fc49e7c97",
      "5645f6b5185cb71a",
      "3fc2c2e6fbeed04d",
      "15471fb5cd8e6c02",
      "125678961d40e093",
      "6ef40ab0c15f2048",
      "a464a708ff451422",
      "60944e05d0857514",
      "ee98b9b50ff783e8",
      "c0390fa228af6dcb",
      "73e06e07ef37cdcc",
      "2f40690aeb53f539"
    ],
    "lengthBlock": "0000014800000218",
    "finalSum": "73cef44bae6bdb61",
    "tag": "a7928069aa10fd10"
  },
  {
    "cipher": "Magma",
    "example": 2,
    "key": "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
    "icn": "0077665544332211",
    "aad": "",
    "plaintext": "22334455667700ff",
    "y": [
      "5b2a7e604f9fbb95"
    ],
    "keystream": [
      "48a6a5170d529db1"
    ],
    "ciphertext": "6a95e1426b259d4e",
    "z": [
      "597354787e52e6eb",
      "597354797e52e6eb"
    ],
    "h": [
      "ece3f9da118c7d95",
      "310c0dacc9d04d93"
    ],
    "runningSum": [
      "25d0e4207b6bf63d"
    ],
    "lengthBlock": "0000000000000040",
    "finalSum": "66d38f120f789249",
    "tag": "334ee270450bec9e"
  }
];
