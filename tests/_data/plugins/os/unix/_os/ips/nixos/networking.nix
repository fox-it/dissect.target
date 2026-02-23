{ lib, ... }: {
  networking = {
    nameservers = [ "10.13.37.1"
 "10.13.37.2"
 ];
    defaultGateway = "10.13.37.0";
    defaultGateway6 = {
      address = "";
      interface = "eth0";
    };
    dhcpcd.enable = false;
    usePredictableInterfaceNames = lib.mkForce false;
    interfaces = {
      eth0 = {
        ipv4.addresses = [
          { address="10.13.37.10"; prefixLength=24; }
        ];
        ipv6.addresses = [
          { address="2001:db8::1"; prefixLength=64; }
        ];
        ipv4.routes = [ { address = "10.13.37.0"; prefixLength = 32; } ];
        ipv6.routes = [ { address = ""; prefixLength = 128; } ];
      };

    };
  };
  services.udev.extraRules = ''
    ATTR{address}=="52:54:00:12:34:56", NAME="eth0"

  '';
}
