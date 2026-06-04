// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
interface Document {
    createXULElement(tagName: string, options?: ElementCreationOptions): XULElement;
}

interface Window {
    readonly gMessageListeners: object[];
    readonly updateExpandedView: () => void;
}
