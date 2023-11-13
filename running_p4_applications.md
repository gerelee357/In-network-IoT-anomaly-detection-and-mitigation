## Running P4 Applications

**1. Start by setting up the environment following the instructions in the "building_p4_env.md" document. Once completed, navigate to the exercises directory:**

```bash
cd ~/tutorials/exercises/
```

**2. Check the available P4 applications developed by P4.org in this directory:**

```bash
ls
```

You will see a list of applications, including "basic," "ecn," "load_balance," and others.

**3. To run a specific application, like the basic packet forwarding application, go to its directory (e.g., "basic") and execute the "make run" command:**

```bash
cd basic
make run
```

**4. For running the DDoS detection and mitigation application (anomaly_detection_mitigation), copy the "anomaly_detection_mitigation" folder from the repository to "~/tutorials/exercises/". Then, execute it similarly to other applications.**

```bash
# Assuming you've copied the folder
cp -r path/to/anomaly_detection_mitigation ~/tutorials/exercises/

# Navigate to the folder and run the application
cd ~/tutorials/exercises/anomaly_detection_mitigation
make run
```

**Note:** The DDoS detection and mitigation application build upon the mri_runtime application, introducing additional features for enhanced anomaly detection and mitigation. Adjustments and improvements can be made based on specific requirements.
