## Running P4 applications
 
**1. After successfully setting up the environment according to the instructions provided in the "building_p4_env.md" document, proceed to the following directory location.**

cd ~/tutorials/exercises/

**2. Upon checking the contents of this directory, you will find P4 applications that have been developed by the P4.org.**

ls

basic         ecn           load_balance  multicast  source_routing
basic_tunnel  firewall      mri           p4runtime
calc          link_monitor  mri_runtime   qos

**3. To execute a specific application, such as the basic packet forwarding application, navigate to the "basic" directory and initiate the process by running the command "make run."**

cd basic

make run

**4. To run my DDoS detection and mitigation application, please copy the "anomaly_detection_mitigation" folder from the repository to the "~/tutorials/exercises/" directory. Subsequently, execute it in the same manner as the other applications.**


**Note:** This application is based on the mri_runtime application and is enhanced by adding additional features for anomaly detection and mitigation.
