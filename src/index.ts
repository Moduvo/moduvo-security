/**
 * MODUVO Security System
 * Copyright (c) 2025 MODUVO. All rights reserved.
 * 
 * This source code is licensed under the MIT license with additional conditions:
 * - Attribution to MODUVO is required in all copies or substantial portions
 * - Removal of copyright or watermarks is prohibited
 * - Any commercial use requires explicit written permission
 */

import express, { Request, Response, NextFunction } from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import { system_guard } from './guards/protect.js'
import { fileURLToPath } from 'url'
import { dirname } from 'path'
import { security } from './security.js'
import os from 'os'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

dotenv.config()

const app = express()
app.use(cors())
app.use(express.json())

const guard = system_guard.start()

app.get('/', (req, res) => {
    const endpoints = {
        '/test/vm': 'Test VM detection',
        '/test/debug': 'Test debugger detection',
        '/test/memory': 'Test memory scan detection',
        '/status': 'Get security status'
    }
    
    res.json({
        success: true,
        data: {
            name: 'MODUVO Security',
            version: '1.0.0',
            status: 'running',
            endpoints
        },
        timestamp: new Date().toISOString()
    })
})

app.get('/test/vm', (req, res) => {
    try {
        const vm_detected = system_guard.test_vm()
        res.json({
            success: true,
            data: {
                test: 'VM Detection',
                result: vm_detected ? 'VM Detected' : 'System appears clean',
                safe: !vm_detected
            },
            timestamp: new Date().toISOString()
        })
    } catch (err) {
        res.status(500).json({
            success: false,
            error: 'VM detection test failed',
            timestamp: new Date().toISOString()
        })
    }
})

app.get('/test/debug', (req, res) => {
    try {
        const debugger_found = process.execArgv.some(arg => arg.includes('--inspect'))
        res.json({
            success: true,
            data: {
                test: 'Debug Detection',
                result: debugger_found ? 'Debugger detected' : 'No debugger found',
                safe: !debugger_found
            },
            timestamp: new Date().toISOString()
        })
    } catch (err) {
        res.status(500).json({
            success: false,
            error: 'Debug detection test failed',
            timestamp: new Date().toISOString()
        })
    }
})

app.get('/test/memory', (req, res) => {
    try {
        const memory = process.memoryUsage()
        const memory_info = {
            heap_used: Math.round(memory.heapUsed / 1024 / 1024),
            heap_total: Math.round(memory.heapTotal / 1024 / 1024),
            external: Math.round(memory.external / 1024 / 1024),
            rss: Math.round(memory.rss / 1024 / 1024)
        }
        
        const suspicious = memory_info.heap_used > memory_info.heap_total * 0.9
        
        res.json({
            success: true,
            data: {
                test: 'Memory Usage',
                ...memory_info,
                safe: !suspicious
            },
            timestamp: new Date().toISOString()
        })
    } catch (err) {
        res.status(500).json({
            success: false,
            error: 'Memory scan test failed',
            timestamp: new Date().toISOString()
        })
    }
})

app.get('/status', (req, res) => {
    try {
        const system_info = {
            uptime: Math.round(process.uptime()),
            memory: {
                used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
                total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
            },
            cpu: {
                count: os.cpus().length,
                model: os.cpus()[0].model,
                speed: os.cpus()[0].speed
            },
            platform: process.platform,
            node_version: process.version,
            environment: process.env.NODE_ENV || 'development'
        }
        
        res.json({
            success: true,
            data: system_info,
            timestamp: new Date().toISOString()
        })
    } catch (err) {
        res.status(500).json({
            success: false,
            error: 'Status check failed',
            timestamp: new Date().toISOString()
        })
    }
})

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error(err.stack)
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        timestamp: new Date().toISOString()
    })
})

app.use((req: Request, res: Response) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        timestamp: new Date().toISOString()
    })
})

const port = process.env.PORT || 3001
app.listen(port, () => console.log(`Security server running on port ${port}`))

export { security }

// Example usage:
// import { security } from 'your-package-name'
// 
// // Initialize security
// security.init()
// 
// // Check if system is safe
// if (security.is_safe()) {
//     console.log('System is secure')
// } else {
//     console.log('Security issues detected')
//     console.log(security.get_status())
// }
