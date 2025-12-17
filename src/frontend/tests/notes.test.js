import { describe, it, expect, vi } from 'vitest'
import { fetchNotes } from '../src/api'

describe('API client', () => {
    it('fetchNotes returns data', async () => {
        global.fetch = vi.fn(() =>
            Promise.resolve({
                json: () => Promise.resolve([{ title: 'test', content: 'hello' }])
            })
        )

        const data = await fetchNotes()
        expect(data.length).toBe(1)
    })
})