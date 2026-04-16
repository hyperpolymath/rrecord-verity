# POST-audit status report
Repo: rrecord-verity
Actions taken:
- Added TS blocker workflow
- Added NPM/Bun blocker workflow
- Managed lockfiles
- Synced repo (Dependabot, .scm, Justfile)
Remaining findings: {
  "program_path": ".",
  "language": "javascript",
  "frameworks": [],
  "weak_points": [
    {
      "category": "InsecureProtocol",
      "location": "experiments/JSDNS.mjs",
      "file": "experiments/JSDNS.mjs",
      "severity": "Medium",
      "description": "3 HTTP (non-HTTPS) URLs in experiments/JSDNS.mjs",
      "recommended_attack": [
        "network"
      ]
    },
    {
      "category": "InsecureProtocol",
      "location": "experiments/libunboundWorker.js",
      "file": "experiments/libunboundWorker.js",
      "severity": "Medium",
      "description": "1 HTTP (non-HTTPS) URLs in experiments/libunboundWorker.js",
      "recommended_attack": [
        "network"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "modules/dkim/favicon.mjs.js",
      "file": "modules/dkim/favicon.mjs.js",
      "severity": "Medium",
      "description": "1 JSON.parse call(s) with 0 try block(s) in modules/dkim/favicon.mjs.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "InsecureProtocol",
      "location": "modules/dnsbl.mjs.js",
      "file": "modules/dnsbl.mjs.js",
      "severity": "Medium",
      "description": "1 HTTP (non-HTTPS) URLs in modules/dnsbl.mjs.js",
      "recommended_attack": [
        "network"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "modules/resultStorage.mjs.js",
      "file": "modules/resultStorage.mjs.js",
      "severity": "Medium",
      "description": "1 JSON.parse call(s) with 0 try block(s) in modules/resultStorage.mjs.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "scripts/update-thirdparty.js",
      "file": "scripts/update-thirdparty.js",
      "severity": "Medium",
      "description": "1 JSON.parse call(s) with 0 try block(s) in scripts/update-thirdparty.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "DynamicCodeExecution",
      "location": "scripts/verify-rsr.js",
      "file": "scripts/verify-rsr.js",
      "severity": "Critical",
      "description": "eval() usage in scripts/verify-rsr.js",
      "recommended_attack": [
        "cpu",
        "memory"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "test/helpers/initWebExtensions.mjs.js",
      "file": "test/helpers/initWebExtensions.mjs.js",
      "severity": "Medium",
      "description": "1 JSON.parse call(s) with 0 try block(s) in test/helpers/initWebExtensions.mjs.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "test/unittest/authVerifierSpec.mjs.js",
      "file": "test/unittest/authVerifierSpec.mjs.js",
      "severity": "Medium",
      "description": "2 JSON.parse call(s) with 0 try block(s) in test/unittest/authVerifierSpec.mjs.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "DynamicCodeExecution",
      "location": "thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "file": "thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "severity": "High",
      "description": "DOM manipulation (innerHTML/document.write) in thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "recommended_attack": [
        "memory",
        "network"
      ]
    },
    {
      "category": "InputBoundary",
      "location": "thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "file": "thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "severity": "Medium",
      "description": "12 JSON.parse call(s) with 8 try block(s) in thirdparty/tabulator-tables/dist/js/tabulator_esm.js — JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "UncheckedError",
      "location": "contractiles/k9/template-hunt.k9.ncl",
      "file": "contractiles/k9/template-hunt.k9.ncl",
      "severity": "Low",
      "description": "14 TODO/FIXME/HACK markers in contractiles/k9/template-hunt.k9.ncl",
      "recommended_attack": [
        "cpu"
      ]
    },
    {
      "category": "SupplyChain",
      "location": "flake.nix",
      "file": "flake.nix",
      "severity": "High",
      "description": "flake.nix declares inputs without narHash, rev pinning, or sibling flake.lock — dependency revision is unpinned in flake.nix",
      "recommended_attack": []
    }
  ],
  "statistics": {
    "total_lines": 60112,
    "unsafe_blocks": 0,
    "panic_sites": 0,
    "unwrap_calls": 4,
    "allocation_sites": 1,
    "io_operations": 36,
    "threading_constructs": 2
  },
  "file_statistics": [
    {
      "file_path": "experiments/libunbound.js",
      "lines": 419,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 0,
      "threading_constructs": 2
    },
    {
      "file_path": "modules/dkim/keyStore.mjs.js",
      "lines": 388,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 3,
      "threading_constructs": 0
    },
    {
      "file_path": "modules/extensionUtils.mjs.js",
      "lines": 180,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 1,
      "threading_constructs": 0
    },
    {
      "file_path": "modules/virusTotalIntegration.mjs.js",
      "lines": 439,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 4,
      "threading_constructs": 0
    },
    {
      "file_path": "scripts/atnChangelog.js",
      "lines": 24,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 1,
      "threading_constructs": 0
    },
    {
      "file_path": "scripts/pack.js",
      "lines": 205,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 4,
      "threading_constructs": 0
    },
    {
      "file_path": "scripts/update-thirdparty.js",
      "lines": 57,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 2,
      "threading_constructs": 0
    },
    {
      "file_path": "test/helpers/testUtils.mjs.js",
      "lines": 109,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 2,
      "threading_constructs": 0
    },
    {
      "file_path": "test/unittest/keyStoreSpec.mjs.js",
      "lines": 209,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 12,
      "threading_constructs": 0
    },
    {
      "file_path": "thirdparty/tabulator-tables/dist/js/tabulator_esm.js",
      "lines": 29671,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 2,
      "threading_constructs": 0
    },
    {
      "file_path": "wasm/crypto/src/lib.rs",
      "lines": 214,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 1,
      "allocation_sites": 0,
      "io_operations": 0,
      "threading_constructs": 0
    },
    {
      "file_path": "wasm/parser/src/lib.rs",
      "lines": 235,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 3,
      "allocation_sites": 1,
      "io_operations": 0,
      "threading_constructs": 0
    },
    {
      "file_path": "setup.sh",
      "lines": 278,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 3,
      "threading_constructs": 0
    },
    {
      "file_path": "flake.nix",
      "lines": 116,
      "unsafe_blocks": 0,
      "panic_sites": 0,
      "unwrap_calls": 0,
      "allocation_sites": 0,
      "io_operations": 2,
      "threading_constructs": 0
    }
  ],
  "recommended_attacks": [
    "disk",
    "memory",
    "cpu",
    "network"
  ],
  "dependency_graph": {
    "edges": [
      {
        "from": "scripts/atnChangelog.js",
        "to": "scripts/pack.js",
        "relation": "shared_dir:scripts",
        "weight": 1.0
      },
      {
        "from": "scripts/pack.js",
        "to": "scripts/update-thirdparty.js",
        "relation": "shared_dir:scripts",
        "weight": 1.0
      },
      {
        "from": "modules/extensionUtils.mjs.js",
        "to": "modules/virusTotalIntegration.mjs.js",
        "relation": "shared_dir:modules",
        "weight": 1.0
      },
      {
        "from": "setup.sh",
        "to": "flake.nix",
        "relation": "shared_dir:",
        "weight": 1.0
      }
    ]
  },
  "taint_matrix": {
    "rows": [
      {
        "source_category": "DynamicCodeExecution",
        "sink_axis": "cpu",
        "severity_value": 5.0,
        "files": [
          "scripts/verify-rsr.js"
        ],
        "frameworks": [],
        "relation": "DynamicCodeExecution->Cpu"
      },
      {
        "source_category": "InsecureProtocol",
        "sink_axis": "network",
        "severity_value": 2.5,
        "files": [
          "experiments/JSDNS.mjs",
          "experiments/libunboundWorker.js",
          "modules/dnsbl.mjs.js"
        ],
        "frameworks": [],
        "relation": "InsecureProtocol->Network"
      },
      {
        "source_category": "DynamicCodeExecution",
        "sink_axis": "memory",
        "severity_value": 5.0,
        "files": [
          "scripts/verify-rsr.js",
          "thirdparty/tabulator-tables/dist/js/tabulator_esm.js"
        ],
        "frameworks": [],
        "relation": "DynamicCodeExecution->Memory"
      },
      {
        "source_category": "UncheckedError",
        "sink_axis": "cpu",
        "severity_value": 1.0,
        "files": [
          "contractiles/k9/template-hunt.k9.ncl"
        ],
        "frameworks": [],
        "relation": "UncheckedError->Cpu"
      },
      {
        "source_category": "DynamicCodeExecution",
        "sink_axis": "network",
        "severity_value": 3.5,
        "files": [
          "thirdparty/tabulator-tables/dist/js/tabulator_esm.js"
        ],
        "frameworks": [],
        "relation": "DynamicCodeExecution->Network"
      },
      {
        "source_category": "InputBoundary",
        "sink_axis": "cpu",
        "severity_value": 2.5,
        "files": [
          "modules/dkim/favicon.mjs.js",
          "modules/resultStorage.mjs.js",
          "scripts/update-thirdparty.js",
          "test/helpers/initWebExtensions.mjs.js",
          "test/unittest/authVerifierSpec.mjs.js",
          "thirdparty/tabulator-tables/dist/js/tabulator_esm.js"
        ],
        "frameworks": [],
        "relation": "InputBoundary->Cpu"
      }
    ]
  }
}
CRG Grade: D
