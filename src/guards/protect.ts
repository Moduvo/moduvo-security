/**
 * MODUVO Key Security System
 * Copyright (c) 2025 MODUVO. All rights reserved.
 * 
 * This source code is licensed under the MIT license with additional conditions:
 * - Attribution to MODUVO is required in all copies or substantial portions
 * - Removal of copyright or watermarks is prohibited
 * - Any commercial use requires explicit written permission
 */

import crypto from 'crypto'
import { execSync } from 'child_process'
import os from 'os'
import { detect_tools } from './detect'
import tls from 'tls'
import fs from 'fs'
import path from 'path'
import net from 'net'

export class system_guard {
    private static instance: system_guard
    private error_count = 0
    private last_check = Date.now()
    private memory_pattern!: Buffer
    private encrypted_data!: Buffer
    private static readonly max_errors = 3
    private static readonly memory_check_interval = 5000
    private static readonly network_check_interval = 3000
    private static readonly process_check_interval = 2000

    static start() {
        if (this.instance) return
        this.instance = new system_guard()
        this.create_key()
        this.initialize_security()
        return this.instance
    }

    private static create_key() {
        const rand_key = crypto.randomBytes(32)
        process.env.sys_key = rand_key.toString('hex')
    }

    private static initialize_security() {
        const memory = Buffer.alloc(1024 * 1024)
        crypto.randomFillSync(memory)
        this.instance.memory_pattern = memory

        const data = Buffer.from('security_data')
        const key = crypto.scryptSync(process.env.sys_key!, 'salt', 32)
        const iv = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
        this.instance.encrypted_data = Buffer.concat([
            iv,
            cipher.update(data),
            cipher.final()
        ])
    }

    static test_vm(): boolean {
        const signs = ['vmware', 'virtualbox', 'qemu', 'xen', 'vbox']
        try {
            const hw = execSync('systeminfo').toString().toLowerCase()
            return signs.some(s => hw.includes(s))
        } catch {
            return false
        }
    }

    static test_memory(): boolean {
        const mem = process.memoryUsage()
        return mem.heapUsed > 500000000
    }

    static test_debug(): boolean {
        return process.execArgv.some(arg => arg.includes('--inspect'))
    }

    constructor() {
        this.check_resources()
        this.check_processes()
        this.check_debugger()
        this.check_virtual()
        this.check_advanced()
        this.advanced_checks()
    }

    private check_resources() {
        const delay = 800 + Math.random() * 400
        setInterval(() => {
            try {
                if (!this.verify_memory_pattern()) {
                    this.log_error('memory integrity compromised')
                }

                if (!this.verify_encrypted_data()) {
                    this.log_error('data integrity compromised')
                }
            } catch (e) {
                console.error('Resource check failed:', e)
            }
        }, delay)
    }

    private verify_memory_pattern(): boolean {
        try {
            const current = Buffer.alloc(this.memory_pattern.length)
            current.fill(0)
            const is_equal = crypto.timingSafeEqual(this.memory_pattern, current)
            if (!is_equal) {
                this.memory_pattern = Buffer.alloc(1024 * 1024)
                crypto.randomFillSync(this.memory_pattern)
            }
            return true
        } catch {
            return true
        }
    }

    private verify_encrypted_data(): boolean {
        try {
            const key = crypto.scryptSync(process.env.sys_key!, 'salt', 32)
            const iv = this.encrypted_data.slice(0, 16)
            const encrypted = this.encrypted_data.slice(16)
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
            decipher.update(encrypted)
            decipher.final()
            return true
        } catch {
            return true
        }
    }

    private check_processes() {
        const delay = 1000 + Math.random() * 1000
        setInterval(() => {
            try {
                if (process.platform === 'win32') {
                    const running = execSync('tasklist').toString().toLowerCase()
                    const dangerous = [
                        'ida.exe', 'ida64.exe', 
                        'x64dbg.exe', 'x32dbg.exe', 'windbg.exe',
                        'ollydbg.exe', 'immunity.exe', 'radare2.exe',
                        'ghidra.exe', 'dnspy.exe', 'hxd.exe',
                        'binaryninja.exe', 'hopper.exe', 'frida.exe',
                        'gdb.exe', 'cheatengine.exe',
                        'wireshark.exe', 'tcpdump.exe', 'proxifier.exe',
                        'charles.exe', 'fiddler.exe', 'burpsuite.exe'
                    ]
                    
                    for (const tool of dangerous) {
                        if (running.includes(tool)) {
                            console.error(`Blocked debugger: ${tool}`)
                            this.error_count = system_guard.max_errors
                            this.log_error('debugger detected')
                            return
                        }
                    }
                }
            } catch (e) {
                console.error('Process check failed:', e)
            }
        }, delay)
    }

    private check_debugger() {
        let last_time = Date.now()
        let consecutive_pauses = 0
        const expected = 1000 
        const max_pauses = 3
        const pause_threshold = 500

        setInterval(() => {
            try {
                const now = Date.now()
                const diff = now - last_time
                
                if (Math.abs(diff - expected) > pause_threshold) {
                    consecutive_pauses++
                    if (consecutive_pauses >= max_pauses) {
                        console.error(`Debug pause detected: ${diff}ms delay`)
                        this.error_count = system_guard.max_errors
                        this.log_error('debugger pause detected')
                    }
                } else {
                    consecutive_pauses = Math.max(0, consecutive_pauses - 1)
                }
                
                last_time = now
            } catch (e) {
                console.error('Debugger check failed:', e)
            }
        }, expected)
    }

    private check_virtual() {
        if (this.is_virtual()) {
            this.log_error('virtual environment detected')
        }
    }

    private is_virtual(): boolean {
        const signs = [
            'vmware',
            'virtualbox',
            'qemu',
            'xen',
            'vbox'
        ]
        
        try {
            const hw = execSync('systeminfo').toString().toLowerCase()
            return signs.some(s => hw.includes(s))
        } catch {
            return false
        }
    }

    private check_advanced() {
        setInterval(() => {
            const hw_threats = detect_tools.check_hardware()
            const net_threats = detect_tools.check_network()
            const sys_threats = detect_tools.check_system()

            const all_threats = [...hw_threats, ...net_threats, ...sys_threats]
            if (all_threats.length > 0) {
                console.error('Advanced threats:', all_threats)
                this.error_count = 3
                this.log_error('system compromised')
            }
        }, 5000 + Math.random() * 2000)
    }

    private async advanced_checks() {
        setInterval(async () => {
            const memory = await detect_tools.check_memory()
            const timing = detect_tools.check_timing()
            
            if (memory.length > 0 || timing.length > 0) {
                this.error_count = 3
                this.log_error('advanced threat detected')
            }
        }, 5000 + Math.random() * 2000)
    }

    private check_network() {
        setInterval(() => {
            try {
                const interfaces = os.networkInterfaces()
                for (const [name, addrs] of Object.entries(interfaces)) {
                    if (!addrs) continue
                    for (const addr of addrs) {
                        if (addr.internal) continue
                        
                        if (name.includes('tun') || name.includes('tap') || 
                            name.includes('ppp') || name.includes('vpn')) {
                            this.log_error('suspicious network interface detected')
                        }
                    }
                }

                const debug_ports = [8080, 9229, 5000, 4444, 5858, 9222]
                for (const port of debug_ports) {
                    const test = new net.Socket()
                    test.setTimeout(100)
                    test.connect(port, '127.0.0.1', () => {
                        this.log_error(`debug port ${port} detected`)
                        test.destroy()
                    })
                }
            } catch (e) {
                this.log_error('network check failed')
            }
        }, system_guard.network_check_interval)
    }

    private log_error(error: string) {
        this.error_count++
        console.error(`Security alert: ${error}`)
        
        try {
            const log_path = path.join(process.cwd(), 'security.log')
            const timestamp = new Date().toISOString()
            fs.appendFileSync(log_path, `[${timestamp}] ${error}\n`)
        } catch (e) {
            console.error('Failed to write security log')
        }

        if (this.error_count >= system_guard.max_errors) {
            this.secure_cleanup()
            process.exit(1)
        }
    }

    private secure_cleanup() {
        try {
            this.memory_pattern.fill(0)
            this.encrypted_data.fill(0)
            process.env.sys_key = ''
            
            const log_path = path.join(process.cwd(), 'security.log')
            if (fs.existsSync(log_path)) {
                fs.unlinkSync(log_path)
            }
        } catch (e) {
            console.error('Secure cleanup failed')
        }
    }
}
