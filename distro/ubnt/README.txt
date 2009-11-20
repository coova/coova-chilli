
The Ubiquiti SDK (http://www.ubnt.com/support/sdk.php) lets you make
changes to the standard Ubiquiti firmware. Here is how to add
CoovaChili and the embedded captive portal. 

Follow directions from Ubiquiti on how to setup the SDK for building a
new firmware. You will have to be running Linux (Ubuntu is their
preference) and will have to have their toolchain installed.

More informration:
http://www.ubnt.com/wiki/index.php/AirOS-SDK
http://www.ubnt.com/wiki/index.php/Setting_up_build_environment_in_Ubuntu_for_re-compiling_AirOS
http://www.ubnt.com/wiki/index.php/Firmware_Recovery

Before proceeding, be sure you are familiar with how to upgrade the
Ubiquiti router firmware and the firmware recovery procedure.

Once you have the necessary toolchain installed and have downloaded
the SDK, go into the SDK directory.

cd /path/to/ubnt-sdk/

Install the necessary source code and install make files. Here is an
example of linking to your existing CoovaChilli source directory and
downloading haserl:

cd apps/gpl
ln -s /path/to/coova-chilli-src coova-chilli
ln -s coova-chilli/distro/ubnt/coova-chilli.mk .
ln -s coova-chilli/distro/ubnt/haserl.mk .
wget http://downloads.sourceforge.net/project/haserl/haserl-devel/0.9.26/haserl-0.9.26.tar.gz
tar xzf haserl-0.9.26.tar.gz 
mv haserl-0.9.26 haserl
cd -

Now, configure the xs2 target with CoovaChilli by apply the patch:

patch -p1 < apps/gpl/coova-chilli/distro/ubnt/xs2.patch

The above patch will do several things, including:

* Enables a couple options in busybox (tr, head, basename, dirname, etc)
* Enables the tun/tap kernel module to be built as a module
* Enables the coova-chilli and haserl apps/gpl packages
* Tries to configure chilli to start on boot-up (not working; looking into it)

To patch the Uniquit web interface for simple CoovaChilli configurations:

patch -p1 < apps/gpl/coova-chilli/distro/ubnt/apps.web.patch

Build the new firmware:

PATH=$PATH:. make clean xs2 

Configure AirOS:

Under the "Link Setup" tab, enable the ''Access Point'' Wireless Mode. Save any apply the changes. 

Under the "Services" tab, configure CoovaChilli:

Need to restore? You can get an original firmware here:

http://www.ubnt.com/downloads/firmwares/XS-fw/v3.5/Bullet2-v3.5.build4494.bin

