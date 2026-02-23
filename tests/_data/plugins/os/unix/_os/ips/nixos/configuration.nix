{ ... }: {
  imports = [
    ./hardware-configuration.nix
    ./networking.nix
  ];

  boot.tmp.cleanOnBoot = true;
  zramSwap.enable = true;
  networking.hostName = "test-nixos";
  networking.domain = "";
  services.openssh.enable = true;
  system.stateVersion = "23.11";
}
