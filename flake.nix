{
  description = "Typst Environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default = let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      pkgs.mkShell {
        buildInputs = [
          pkgs.go
	  pkgs.gotools
	  pkgs.gopls
	  pkgs.golangci-lint
        ];
      };
    });
}
