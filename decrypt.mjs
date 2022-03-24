import nacl from './vendor/nacl.js'
import fs from 'fs'
import path from 'path'

const chars = new Map(
  [
    '◰',
    '◱',
    '◲',
    '◳',
    '◴',
    '◵',
    '◶',
    '◷',
    '◸',
    '◹',
    '◺',
    '◿',
    '◢',
    '◣',
    '◤',
    '◥',
  ].map((c, i) => [c, i.toString(16)]),
)
const bufs = []
for await (const chunk of process.stdin) {
  bufs.push(chunk)
}

const ciphertext = Buffer.concat(bufs).toString('utf8')
const buffer = Buffer.from(
  [...ciphertext].map((x) => chars.get(x) || '').join(''),
  'hex',
)
const sk = Buffer.from(
  fs.readFileSync(path.join(process.env.HOME, '.todecryptkey'), 'utf8'),
  'base64',
)
const pk = buffer.slice(0, 32)
const nonce = buffer.slice(32, 56)
const msg = buffer.slice(56)
const str = Buffer.from(nacl.box.open(msg, nonce, pk, sk)).toString()
const pad = str.match(/^=*>/)[0]
console.log(str.slice(pad.length))
