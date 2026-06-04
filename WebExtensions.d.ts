// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
declare module browser {
    declare module accounts {
        // https://github.com/thundernest/webext-docs/issues/56
        var get: (accountId: string) => Promise<MailAccount?>;
    }
}
