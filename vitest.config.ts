import { defineConfig } from 'vitest/config'

export default defineConfig({
    test: {
        include: [
            'packages/*/src/**/*.test.ts',
            'packages/*/tests/**/*.test.ts',
            'src/**/*.test.ts',
            'tests/**/*.test.ts',
        ],
        exclude: [
            'packages/edge-sensor/tests/sensor.test.ts',
        ],
        testTimeout: 10000,
    },
})
