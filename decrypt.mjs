import nacl from './vendor/nacl.js'
import fs from 'fs'
import path from 'path'

const decode = (ciphertext) => {
  let m
  if ((m = ciphertext.match(/◔([^]*)◕/))) {
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
    return Buffer.from([...m[1]].map((x) => chars.get(x) || '').join(''), 'hex')
  }
  if ((m = ciphertext.match(/(?:⡇|⡏)([^]*)(?:⢸|⣸)/))) {
    return Buffer.from(
      [...m[1]].flatMap((x) => {
        const charCode = x.charCodeAt(0)
        return charCode >= 0x2800 && charCode <= 0x28ff
          ? [charCode - 0x2800]
          : []
      }),
    )
  }
}

const bufs = []
for await (const chunk of process.stdin) {
  bufs.push(chunk)
}

const ciphertext = Buffer.concat(bufs).toString('utf8')
const buffer = decode(ciphertext)

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
