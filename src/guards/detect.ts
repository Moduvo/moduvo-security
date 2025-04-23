/**
 * MODUVO Key Security System
 * Copyright (c) 2025 MODUVO. All rights reserved.
 * 
 * This source code is licensed under the MIT license with additional conditions:
 * - Attribution to MODUVO is required in all copies or substantial portions
 * - Removal of copyright or watermarks is prohibited
 * - Any commercial use requires explicit written permission
 */

import { execSync } from 'child_process'
import crypto from 'crypto'
import os from 'os'
import net from 'net'
import fs from 'fs'
import path from 'path'

export class detect_tools {
    private static last_check = Date.now()
    private static readonly suspicious_patterns = [
        'inject', 'hook', 'patch', 'debug',
        'monitor', 'sniff', 'proxy', 'tunnel',
        'sandbox', 'virtual', 'vmware', 'vbox'
    ]

    static check_hardware(): string[] {
        const threats = []
        try {
            const cpu = os.cpus()[0].model
            if (cpu.includes('QEMU') || cpu.includes('Virtual') || 
                cpu.includes('VMware') || cpu.includes('Hyper-V')) {
                threats.push('virtual_cpu')
            }

            if (process.platform === 'win32') {
                try {
                    const gpu_info = os.cpus()[0].model
                    if (gpu_info.includes('VMware') || 
                        gpu_info.includes('Virtual') || 
                        gpu_info.includes('QEMU')) {
                        threats.push('virtual_gpu')
                    }

                    const disk_info = os.homedir()
                    if (disk_info.includes('Virtual') || 
                        disk_info.includes('VMware') || 
                        disk_info.includes('QEMU')) {
                        threats.push('virtual_disk')
                    }

                    const bios_info = os.platform()
                    if (bios_info.includes('VMware') || 
                        bios_info.includes('VIRTUAL') || 
                        bios_info.includes('QEMU')) {
                        threats.push('virtual_bios')
                    }

                    const mb_info = os.arch()
                    if (mb_info.includes('Virtual') || 
                        mb_info.includes('VMware') || 
                        mb_info.includes('QEMU')) {
                        threats.push('virtual_motherboard')
                    }

                    const usb_info = os.networkInterfaces()
                    let virtual_usb_count = 0
                    for (const [name, addrs] of Object.entries(usb_info)) {
                        if (name.includes('Virtual') || 
                            name.includes('VMware') || 
                            name.includes('QEMU')) {
                            virtual_usb_count++
                        }
                    }
                    if (virtual_usb_count >= 2) {
                        threats.push('virtual_usb')
                    }
                } catch (e) {
                    console.error('Hardware check failed:', e)
                }
            }
        } catch (e) {
            console.error('Hardware check failed:', e)
        }
        return threats
    }

    static check_network(): string[] {
        const threats = []
        try {
            const interfaces = os.networkInterfaces()
            let suspicious_count = 0
            
            for (const [name, addrs] of Object.entries(interfaces)) {
                if (!addrs) continue
                
                for (const addr of addrs) {
                    if (addr.mac && (
                        addr.mac.startsWith('00:0C:29') ||
                        addr.mac.startsWith('00:50:56') ||
                        addr.mac.startsWith('00:1C:14') ||
                        addr.mac.startsWith('00:05:69')
                    )) {
                        suspicious_count++
                    }

                    if (name.includes('tun') || name.includes('tap')) {
                        suspicious_count++
                    }
                }
            }

            if (suspicious_count >= 2) {
                threats.push('suspicious_network')
            }

            const proxy_count = [
                process.env.HTTP_PROXY,
                process.env.HTTPS_PROXY,
                process.env.ALL_PROXY
            ].filter(Boolean).length

            if (proxy_count >= 2) {
                threats.push('proxy_detected')
            }
        } catch (e) {
            console.error('Network check failed:', e)
        }
        return threats
    }

    static check_system(): string[] {
        const threats = []
        try {
            const debug_methods = [
                () => process.execArgv.some(arg => arg.includes('--inspect')),
                () => process.env.NODE_OPTIONS?.includes('--inspect'),
                () => process.env.NODE_OPTIONS?.includes('--debug')
            ]
            
            const debug_detections = debug_methods.filter(method => method())
            if (debug_detections.length >= 2) {
                threats.push('debugger_present')
            }

            const env = process.env
            const suspicious_count = Object.entries(env).filter(([key, value]) => 
                value && this.suspicious_patterns.some(pattern => 
                    key.toLowerCase().includes(pattern) || 
                    value.toLowerCase().includes(pattern))
            ).length

            if (suspicious_count >= 2) {
                threats.push('suspicious_environment')
            }
        } catch (e) {
            console.error('System check failed:', e)
        }
        return threats
    }

    static check_timing(): string[] {
        const threats = []
        try {
            const now = Date.now()
            const diff = now - this.last_check
            
            if (this.last_check > 0) {
                if (diff > 5000 || diff < 200) {
                    const verify1 = process.hrtime()
                    crypto.randomBytes(1024)
                    const [s1, ns1] = process.hrtime(verify1)
                    const verify2 = process.hrtime()
                    crypto.randomBytes(1024)
                    const [s2, ns2] = process.hrtime(verify2)
                    
                    if ((s1 * 1e9 + ns1 > 1000000) && (s2 * 1e9 + ns2 > 1000000)) {
                        threats.push('timing_anomaly')
                    }
                }
            }

            this.last_check = now
        } catch (e) {
            console.error('Timing check failed:', e)
        }
        return threats
    }

    static async check_memory(): Promise<string[]> {
        const threats = []
        try {
            const mem = process.memoryUsage()
            
            const samples = []
            for (let i = 0; i < 3; i++) {
                samples.push(process.memoryUsage().heapUsed)
                await new Promise(resolve => setTimeout(resolve, 100))
            }
            
            const growth_rate = (samples[2] - samples[0]) / samples[0]
            
            if (mem.heapUsed > 1500000000 && growth_rate > 0.1) {
                const final_check = process.memoryUsage()
                if (final_check.heapUsed > 1500000000) {
                    threats.push('excessive_memory_usage')
                }
            }
        } catch (e) {
            console.error('Memory check failed:', e)
        }
        return threats
    }
}
