/**
 * MODUVO Security System
 * Copyright (c) 2025 MODUVO. All rights reserved.
 * 
 * This source code is licensed under the MIT license with additional conditions:
 * - Attribution to MODUVO is required in all copies or substantial portions
 * - Removal of copyright or watermarks is prohibited
 * - Any commercial use requires explicit written permission
 */

import { system_guard } from './guards/protect.js'

export class security {
    private static instance: security
    private guard: any

    static init() {
        if (this.instance) return this.instance
        this.instance = new security()
        this.instance.guard = system_guard.start()
        return this.instance
    }

    static check_vm(): boolean {
        return system_guard.test_vm()
    }

    static check_debug(): boolean {
        return system_guard.test_debug()
    }

    static check_memory(): boolean {
        return system_guard.test_memory()
    }

    static get_status() {
        return {
            vm_detected: this.check_vm(),
            debugger_detected: this.check_debug(),
            memory_safe: !this.check_memory(),
            timestamp: new Date().toISOString()
        }
    }

    static is_safe(): boolean {
        return !this.check_vm() && !this.check_debug() && !this.check_memory()
    }
} 