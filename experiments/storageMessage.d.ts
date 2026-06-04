// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
declare module browser {
    declare module storageMessage {
        const set: (messageId: number, key: string, value: string) => Promise<void>;
        const get: (messageId: number, key: string) => Promise<string>;
    }
}
