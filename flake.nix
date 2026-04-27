{
  description = "SpecMon development environment";

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
          pkgs.go_1_26
	  pkgs.gotools
	  pkgs.gofumpt
	  pkgs.gopls
	  pkgs.golangci-lint
	  pkgs.nodejs
	  pkgs.pnpm
        ];
      };
    });
}
