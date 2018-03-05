### Installation ###

* Install ```RADIUS Server``` from Synology package center
* Open RADIUS Server properties, add client
  edgerouter name, password, ip addr, subnet mask
* In /root directory, run ``` git clone https://github.com/mikesart/radauth ```
* Add ```exec_radauth``` section to radiusd.conf modules section
```
/volume1/@appstore/RadiusServer/etc/raddb/radiusd.conf

    modules {
        exec exec_radauth {
            program = "/root/radauth/radauth.sh"
            wait = yes
            input_pairs = request
            output_pairs = reply
        }
```
* add exec_radauth to authorize / authenticate sections
```
/usr/local/synoradius/rad_site_def_local

    authorize {
        update control {
            Auth-Type := exec_radauth
        }
        # comment out other entries

    ...

    authenticate {
        exec_radauth
        # comment out other entries
```
* update apparmor profile to allow running our radauth script
```
/etc/apparmor.d/pkg_RadiusServer

        ...
        /usr/local/etc/certificate/RadiusServer/radiusd/*               r,

        # radauth.sh
        /root/radauth/       rwkl,
        /root/radauth/**     rwkmixl,
        /usr/bin/python2.7   rix,
        /usr/lib/**          mr,
        /etc/passwd          r,
        /usr/syno/etc/preference/*/google_authenticator r,
    }
```
* reload above config changes
```
  stop / start radius server in package center
  /usr/syno/etc.defaults/rc.sysv/apparmor.sh stop
  /usr/syno/etc.defaults/rc.sysv/apparmor.sh start
```

### Radius notes ###
* reboot synology:
``` synopoweroff -r ```
* check open ports: ```netstat -pat | grep LISTEN```
* to run debug radius server (after stopping radius server in control panel)
```
sudo /volume1/@appstore/RadiusServer/sbin/radiusd -X
```
* Verbose logging to radius server package
```
/volume1/@appstore/RadiusServer/syno_bin/RadiusServer.sh
add -xx to /var/packages/RadiusServer/target/sbin/radiusd line
```
* make Radius re-read its configuration files
```
sudo xargs kill -HUP < /var/packages/RadiusServer/target/var/run/radiusd/radiusd.pid
```
* synology radius tips: https://forum.synology.com/enu/viewtopic.php?t=97698
* radius log file: ```/volume1/@appstore/RadiusServer/var/log/radius/radius.log```
* radius directories
```
/usr/local/synoradius
/var/packages/RadiusServer/target/etc/raddb
/volume1/@appstore/RadiusServer/etc/raddb
/volume1/@appstore/RadiusServer/etc/raddb/modules
```
* test radius server from PC (radclient in freeradius-utils package)
```
echo "User-Name=mikesart,User-Password=password123456" | ./radclient -s 10.10.10.61 auth supersecret
```

### AppArmor notes ###
* apparmor status: ```sudo aa-status```
* apparmor log: ```/var/log/apparmor.log```
* reload apparmor profile: ```apparmor_parser -r /etc/apparmor.d/pkg_RadiusServer```
* reload apparmor profile in 'complain' mode (not enforce mode):
```
apparmor_parser -C -r /etc/apparmor.d/pkg_RadiusServer
```
* stop apparmor
```
/usr/syno/etc.defaults/rc.sysv/apparmor.sh stop
/usr/syno/etc.defaults/rc.sysv/apparmor.sh start
```
* disable apparmor: https://forum.synology.com/enu/viewtopic.php?t=125909
* https://en.opensuse.org/SDB:AppArmor_geeks
```
      r    - read
      w    - write
      ux   - unconstrained execute
      Ux   - unconstrained execute -- scrub the environment
      px   - discrete profile execute
      Px   - discrete profile execute -- scrub the environment
      ix   - inherit execute
      m    - allow PROT_EXEC with mmap(2) calls
      l    - link
      k    - lock
```

### Links ###
* Remote Access to EdgeMAX GUI?  
https://community.ubnt.com/t5/EdgeMAX/Quickly-Enable-Remote-Access-to-EdgeMAX-GUI/td-p/896402
* WAN_IN vs WAN_LOCAL  
https://community.ubnt.com/t5/EdgeMAX/What-is-WAN-IN-vs-WAN-LOCAL/td-p/1098853
* EdgeRouter - L2TP IPsec VPN Server using RADIUS  
https://help.ubnt.com/hc/en-us/articles/115010359067
* Dyn DDNS on EdgeRouter (namecheap)  
https://loganmarchione.com/2017/10/dyn-ddns-edgerouter/
* EdgeRouter - Add other Debian packages to EdgeOS (screen, iftop, iptraf, mtr-tiny, procinfo, bmon)  
https://help.ubnt.com/hc/en-us/articles/205202560-EdgeMAX-Add-other-Debian-packages-to-EdgeOS
* EdgeRouter Configuration articles  
https://help.ubnt.com/hc/en-us/sections/200887544-EdgeRouter-Configuration?page=1#articles
* EdgeMAX KB articles, latest software, etc  
https://help.ubnt.com/hc/en-us/categories/200321064-EdgeMAX
* Ubiquiti reddit forum  
https://www.reddit.com/r/Ubiquiti/
* EdgeMAX Router forums  
https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX
* List of community-contributed feature wizards (ie, VPN Status)  
https://community.ubnt.com/t5/EdgeMAX-Beta/List-of-community-contributed-feature-wizards/m-p/1524500#M15688
* Synology packages source tgz files (RadiusServer, etc)  
https://sourceforge.net/projects/dsgpl/files/Packages/DSM%205.2%20Package%20Release/

### Linux L2TP/IPSec Network Manager packages ###
```
libreswan
network-manager-l2tp
network-manager-l2tp-gnome
xl2tpd
```

### EdgeRouter Dyn DDNS ###

https://loganmarchione.com/2017/10/dyn-ddns-edgerouter/
```
  configure
  set service dns dynamic interface eth0 service dyndns host-name <hostname.dyn.com>
  set service dns dynamic interface eth0 service dyndns login <username>
  set service dns dynamic interface eth0 service dyndns password <password_here>
  commit
  save 

  show dns dynamic status
```

### EdgeRouter commands ###
```
show date
show version
show system image
show system storage
show dhcp leases

; show VPN status
show vpn ipsec sa

show firewall
show configuration all

show configuration commands

show vpn remote-access
show interfaces
show log | match pppd

add system image ?
add system image https://dl.ubnt.com/firmwares/edgemax/v1.10.x/ER-e50.v1.10.0-beta.3.5051713.tar
add system image blah.tar
set system image default-boot
delete system image
```

```
; Step 3: Enable Performance Features
; https://help.ubnt.com/hc/en-us/articles/115002531728-EdgeRouter-Beginners-Guide-to-EdgeRouter
show ubnt offload

show hardware temperature
```

```
; config file: /config/config.boot
configure
load /home/jeffr/config.boot
compare ; compare changes
commit ; or discard
save
exit
```

```
set service dhcp-server shared-network-name LAN1 subnet 192.168.168.0/24 static-mapping durango-dev ip-address 192.168.168.195
set service dhcp-server shared-network-name LAN1 subnet 192.168.168.0/24 static-mapping durango-dev mac-address '20:25:22:22:22:0f'
```

```
; This setting updates the hosts file on the Edgerouter with the name of the
; device and IP address assigned by DHCP. This gives you name resolution for your
; LAN assuming that that the Edgerouter is the DNS server for the LAN.
set service dhcp-server hostfile-update enable
```

```
; alias so you can access device1 directly
set system static-host-mapping host-name device1.<yourdomain> alias device1
```
