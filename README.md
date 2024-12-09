# Databricks AI Security Framework (DASF) AI assistant (DASF AI assistant)

> [!WARNING] 
> This is **not** an officially endorsed Databricks product or solution; use it at your own risk! This is not a supported solution. 
> This is an experimental companion tool for the DASF compendium.

## Setup

* **Step 1:** Choose a workspace in which to run your Databricks AI Security Framework (DASF) AI assistant   
* **Step 2:** Clone [**_this repo_**](https://github.com/arunpamulapati/dasf_assistant) into your chosen workspace
* **Step 3:** Identify the user or service principal you're going to setup the DASF AI assistant with. They will need at least the following permissions:
    * The ability to create schemas/tables/volumes/functions in the target catalog
    * The ability to create DB SQL warehouses and use Genie
* **Step 4:** Connect the [setup.py](notebooks/setup.py) notebook to an serverless or assigned Access mode cluster
* **Step 5:** Run the [setup.py](notebooks/setup.py) notebook, replacing the notebook defaults where necessary:
    * `catalog`: The catalog to use for the DASF AI assistant (all of the tables and functions created by the [setup.py](notebooks/setup.py) notebook will be created in this catalog)
    * `schema`: The schema to use for the DASF AI assistant (all of the tables and functions created by the [setup.py](notebooks/setup.py) notebook will be created in this schema). This schema needs to be in the same catalog specified above.
    * `volume`: The volume in which DASF risks and control files will be stored prior to being loaded in unity catalog. This schema needs to be in the same catalog specified above.
* **Step 6:** Create a new Genie Space ([AWS](https://docs.databricks.com/en/genie/index.html#create-a-new-genie-space), [Azure](https://learn.microsoft.com/en-us/azure/databricks/genie/#create-a-new-genie-space), [GCP](https://docs.gcp.databricks.com/en/genie/index.html#create-a-new-genie-space)):
    * _Copy and paste the [instructions.txt](resources/instructions.txt) into the General Instructions field_
    * _Select the SQL tables and functions created automatically by the [setup.py](notebooks/setup.py) notebook via the Add SQL Functions button_
*  **Step 7:** Ask me away!
   * _You can find some examples of the kinds of questions you can ask in the [questions.txt](resources/questions.txt) file provided!_

## Examples

