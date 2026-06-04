// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
declare module browser {
    declare module mailUtils {
        const getBaseDomainFromAddr: (addr: string) => Promise<string>;
    }
}
