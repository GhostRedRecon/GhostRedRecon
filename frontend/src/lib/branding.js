import { BRAND_KEY } from './brandKey'
import { BRAND_PART_A } from './brandPartA'
import { BRAND_PART_B } from './brandPartB'

function interleaveChunks(evenChunk = [], oddChunk = []) {
  const size = Math.max(evenChunk.length, oddChunk.length)
  const merged = []
  for (let index = 0; index < size; index += 1) {
    if (index < evenChunk.length) merged.push(evenChunk[index])
    if (index < oddChunk.length) merged.push(oddChunk[index])
  }
  return merged
}

function decodeBrandValue(name) {
  const encoded = interleaveChunks(BRAND_PART_A[name], BRAND_PART_B[name])
  return encoded.map((value, index) => String.fromCharCode(value ^ BRAND_KEY[index % BRAND_KEY.length])).join('')
}

export const BRANDING = Object.freeze({
  product: decodeBrandValue('product'),
  tagline: decodeBrandValue('tagline'),
  developed: decodeBrandValue('developed'),
  support: decodeBrandValue('support'),
  supportUrl: decodeBrandValue('supportUrl'),
})
