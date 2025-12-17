# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Jonathan D.A. Jewell
# flake.nix — rrecord-verity (DKIM Verifier)
#
# Nix flake for reproducible development environment
# Usage: nix develop (or nix shell)
{
  description = "RRecord-Verity - Comprehensive email security suite for Thunderbird";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        # Development shell with all build dependencies
        devShells.default = pkgs.mkShell {
          name = "rrecord-verity-dev";

          buildInputs = with pkgs; [
            # Node.js environment (required: >= 22.0.0)
            nodejs_22
            nodePackages.npm

            # Development tools
            git

            # Optional: for manual testing with Thunderbird
            # thunderbird

            # Security tools (optional)
            # nodePackages.snyk
          ];

          shellHook = ''
            echo "🔐 RRecord-Verity Development Environment"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "Node.js: $(node --version)"
            echo "npm:     $(npm --version)"
            echo ""
            echo "Commands:"
            echo "  npm install     - Install dependencies"
            echo "  npm run lint    - Run linter"
            echo "  npm run checkJs - Type checking"
            echo "  npm run test    - Run tests"
            echo "  npm run verify  - Run all checks"
            echo "  npm run pack    - Package extension"
            echo ""
          '';

          # Environment variables
          NODE_ENV = "development";
        };

        # Package definition (for building the extension)
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "rrecord-verity";
          version = "0.1.0";
          src = ./.;

          buildInputs = with pkgs; [
            nodejs_22
            nodePackages.npm
          ];

          buildPhase = ''
            export HOME=$TMPDIR
            npm ci --ignore-scripts
            npm run pack
          '';

          installPhase = ''
            mkdir -p $out
            cp dkim_verifier-*.xpi $out/ || true
          '';

          meta = with pkgs.lib; {
            description = "Comprehensive email security suite for Thunderbird with DKIM, SPF, DMARC verification";
            homepage = "https://github.com/lieser/dkim_verifier";
            license = licenses.mit;
            platforms = platforms.all;
            maintainers = [];
          };
        };

        # Formatter for nix files
        formatter = pkgs.nixpkgs-fmt;
      });
}
