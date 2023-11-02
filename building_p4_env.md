**1. Install Ubuntu 20.04**
- Create a user named p4 and set the password to p4 during Ubuntu installation.
- After the installation, please don't upgrade OS.


 **2. Download the following tutorials**
 
	git clone https://github.com/p4lang/tutorials
	
**2. Copy vm-ubuntu20.04 to /home/p4.**

    cp vm-ubuntu20.04/*  /home/p4
    
    (then delete tutorials)

**3. Run the following scripts to install necessary package.** 

	- sudo     ./root-dev-bootstrap.sh
 
 When running the following script, if the error is encountered, do the installation manually according to the script. 
 
	- sudo ./user-common-bootstrap.sh  
 
	- sudo ./user-dev-bootstrap.sh
	
	
