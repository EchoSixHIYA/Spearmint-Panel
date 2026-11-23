import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

export const digestBytes = (data: Uint8Array) => bytesToHex(sha256(data))
export async function digestFile(file: File, progress: (size: number) => void, alive: () => boolean) {
  const hash = sha256.create()
  const step = 1024 * 1024
  for (let offset = 0; offset < file.size; offset += step) {
    if (!alive()) throw new Error('文件读取已暂停，可重新选择文件后继续。')
    hash.update(new Uint8Array(await file.slice(offset, offset + step).arrayBuffer()))
    progress(Math.min(offset + step, file.size))
    // Keep input and paint responsive even for multi-hundred-megabyte archives.
    await new Promise(resolve => setTimeout(resolve, 0))
  }
  return bytesToHex(hash.digest())
}
