{
  description = "wisp - a fast, lightweight nostr relay written in Zig";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          wisp = pkgs.callPackage ./nix/package.nix { src = self; };
          default = self.packages.${system}.wisp;
        }
      );

      overlays.default = final: _prev: {
        wisp = final.callPackage ./nix/package.nix { src = self; };
      };

      # The module defaults services.wisp.package to this flake's build, so consumers get a working
      # relay from `imports = [ wisp.nixosModules.wisp ]` alone (no overlay required).
      nixosModules.wisp =
        { pkgs, lib, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.wisp.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.wisp;
        };
      nixosModules.default = self.nixosModules.wisp;

      checks = forAllSystems (system: {
        wisp-module = (pkgsFor system).testers.runNixOSTest (import ./nix/test.nix self);
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
