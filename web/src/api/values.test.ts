import { describe, expect, it } from 'vitest'
import { formatLabels, parseLabels, parseSelector } from './values'

describe('label text round trip', () => {
  it.each([
    ['CJK value with a space', { team: '研发 团队' }],
    ['value with a comma', { team: 'ops,platform' }],
    ['value with a space', { a: 'north west' }],
    ['value with a colon', { a: 'b:c' }],
    ['value with a slash', { a: 'b/c' }],
    ['key with a slash', { 'k8s.io/x': 'v' }],
  ])('keeps %s intact', (_name, labels) => {
    expect(parseLabels(formatLabels(labels))).toEqual(labels)
  })
  it('keeps every label of a mixed set intact', () => {
    const labels = {
      team: '研发 团队',
      env: 'prod',
      'k8s.io/x': 'a,b',
      empty: '',
    }
    expect(parseLabels(formatLabels(labels))).toEqual(labels)
  })
  it('reads one key=value per line and ignores blank lines', () => {
    expect(parseLabels('a=1\n\n  \nb=x=y\r\nc=\n')).toEqual({
      a: '1',
      b: 'x=y',
      c: '',
    })
  })
  it('rejects a line without a separator and duplicate keys', () => {
    expect(() => parseLabels('a')).toThrow('error.labels')
    expect(() => parseLabels('a=1\na=2')).toThrow('error.labels')
  })
})

describe('host selector text', () => {
  it('stays comma separated with a restricted charset', () => {
    expect(parseSelector('env=prod, reported.os=linux')).toEqual({
      env: 'prod',
      'reported.os': 'linux',
    })
    expect(() => parseSelector('env=a b')).toThrow('error.labels')
    expect(() => parseSelector('env=prod\ntier=web')).toThrow('error.labels')
  })
})
