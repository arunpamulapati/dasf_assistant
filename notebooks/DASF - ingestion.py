# Databricks notebook source
# MAGIC %md
# MAGIC # Databricks AI Security Framework (DASF) AI assistant 
# MAGIC ## DASF risks and controls ingestion notebook
# MAGIC ### This notebook ingests risks and controls as documented in DASF into the configured unity catalog. It also created the necessary UC functions to help with Genie spaces.

# COMMAND ----------

# MAGIC %md
# MAGIC #Environment setup

# COMMAND ----------

catalogs = list(filter(None, [x.catalog for x in sql("SHOW CATALOGS").limit(1000).collect()]))
dbutils.widgets.dropdown(name="catalog", defaultValue=catalogs[0], choices=catalogs, label="catalog")
dbutils.widgets.text(name="schema", defaultValue="dasf", label="schema")
dbutils.widgets.text(name="volume", defaultValue="dasf", label="volume")


# COMMAND ----------

catalog = dbutils.widgets.get("catalog")
schema = dbutils.widgets.get("schema")
volume = dbutils.widgets.get("volume")

# COMMAND ----------

# define the catalog, schema, and volume names below

sql(f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema}")
sql(f"CREATE VOLUME IF NOT EXISTS {catalog}.{schema}.{volume}")
volume_path = f"/Volumes/{catalog}/{schema}/{volume}"
#volume_path = "../resources/"

sql(f"USE CATALOG {catalog}")
sql(f"USE SCHEMA {schema}")

# COMMAND ----------

import shutil
import os

source_folder = "../resources"
destination_folder = volume_path

# Create destination folder if it doesn't exist
os.makedirs(destination_folder, exist_ok=True)

# Copy files from source to destination
for filename in os.listdir(source_folder):
    source_file = os.path.join(source_folder, filename)
    destination_file = os.path.join(destination_folder, filename)
    if os.path.isfile(source_file):
        shutil.copy(source_file, destination_file)

# COMMAND ----------

# MAGIC %md
# MAGIC #AI Lifecycle Risks

# COMMAND ----------

# Read the AI Lifecycle Risks file into a Spark DataFrame
# The file is located in the specified catalog, schema, and volume
# The file has a header, schema is inferred, and the delimiter is a tab
df_AI_Lifecycle_Risks = spark.read.format("csv").option("header", True).option("inferSchema", True).option("delimiter", "\t").load(f"{volume_path}/Databricks AI Security Framework - AI Lifecycle Risks.tsv")

# Display the DataFrame
display(df_AI_Lifecycle_Risks)

# COMMAND ----------

from pyspark.sql.functions import split, trim

# Extract the 'Risk name' from the 'Risk' column by splitting the string at ':' and trimming any leading/trailing spaces
df_AI_Lifecycle_Risks = df_AI_Lifecycle_Risks.withColumn("Risk name", trim(split(df_AI_Lifecycle_Risks["Risk"], ":")[1]))

# Display the 'Risk name' column to verify the transformation
display(df_AI_Lifecycle_Risks.select("Risk name"))

# COMMAND ----------

# Select and rename columns from the df_AI_Lifecycle_Risks DataFrame
risks_in_ai_system_components = df_AI_Lifecycle_Risks.selectExpr(
    "`Risk Id` as risk_id", 
    "`System component` as system_component", 
    "`Risk` as risk", 
    "`Risk name` as risk_name", 
    "`Risk description` as risk_description", 
    "`Mitigation Controls IDs` as mitigation_control_ids", 
    "`Mitigation controls` as mitigation_controls", 
    "`DASF  Revision` as revision",  
    "`Predictive ML models` as is_predictive_ml_models", 
    "`RAG - LLMs` as is_rag_llms", 
    "`Fine-tuned LLMs` as is_fine_tuned_llms", 
    "`Pre-trained LLMs` as is_pre_trained_llms", 
    "`Foundational LLMs` as is_foundational_llms", 
    "`External models` as is_external_models", 
    "`Initial AI Risk Impacts` as initial_ai_risk_impacts", 
    "`Business Impacts` as business_impacts", 
    "`AI Novelty` as ai_novelty", 
    "`MITRE ATLAS as of Q3 2024` as mitre_atlas_as_of_q3_2024", 
    "`MITRE ATTACK as of Q3 2024` as mitre_attack_as_of_q3_2024", 
    "`OWASP LLM Top 10 2025` as owasp_llm_top_10_2025", 
    "`OWASP ML Top 10 v0.3` as owasp_ml_top_10_v0_3", 
    "`NIST - 800- 53 - Rev 5` as nist_800_53_rev_5", 
    "`NIST 800-53 Controls Mapping Rationale` as nist_800_53_controls_mapping_rationale", 
    "`HITRUST` as hitrust", 
    "`ENISA’s Securing ML Algorithms` as enisa_securing_ml_algorithms", 
    "`ISO 42001:2023 Controls Objectives and Controls (Annex A)` as iso_42001_2023_controls_objectives_and_controls_annex_a", 
    "`ISO 27001:2022 Information Security Control Reference (Annex A)` as iso_27001_2022_information_security_control_reference_annex_a", 
    "`EU AI Act` as eu_ai_act"
)

# Display the transformed DataFrame
display(df_AI_Lifecycle_Risks)

# COMMAND ----------

# Write the DataFrame to a table with specified options
risks_in_ai_system_components.write \
    .option("overwriteSchema", "true") \
    .option("description", "The databricks_ai_mitigation_controls table contains information about the mitigation controls used in the AI system as documented in Databricks AI Security Framework (DASF) white paper. It provides details on the mitigation control, risk mapping, and description of each mitigation control. Additionally, it includes references to Databricks shared responsibility, product documentation links for AWS, Azure, and GCP ,  as well as DASF revision information. The table also includes information on security control types, AI system components and steps, security analysis tools, AI system novelty, and various security standards such as MITRE Atlas, MITRE ATT&CK, OWASP LLM Top 10, OWASP ML Top 10, ISO 42001, and ISO 27001.") \
    .option("tags", "AI, Risks, System Components") \
    .saveAsTable(f"{catalog}.{schema}.risks_in_ai_system_components", mode="overwrite")

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_components table
# MAGIC SELECT * FROM risks_in_ai_system_components

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function that returns a table with specific columns
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_components() RETURNS TABLE (
# MAGIC   risk_id STRING COMMENT 'Risk ID', -- Column for Risk ID
# MAGIC   system_component STRING COMMENT 'System Component Category', -- Column for System Component Category
# MAGIC   risk_name STRING COMMENT 'Full Risk Title' -- Column for Full Risk Title
# MAGIC   -- Additional columns can be uncommented and added as needed
# MAGIC   -- risk_description STRING,
# MAGIC   -- mitigation_control_ids STRING,
# MAGIC   -- mitigation_controls STRING,
# MAGIC   -- revision STRING,
# MAGIC   -- is_predictive_ml_models STRING,
# MAGIC   -- is_rag_llms STRING,
# MAGIC   -- is_fine_tuned_llms STRING,
# MAGIC   -- is_pre_trained_llms STRING,
# MAGIC   -- is_foundational_llms STRING,
# MAGIC   -- is_external_models STRING,
# MAGIC   -- initial_ai_risk_impacts STRING,
# MAGIC   -- business_impacts STRING,
# MAGIC   -- ai_novelty STRING,
# MAGIC   -- mitre_atlas_as_of_q3_2024 STRING,
# MAGIC   -- mitre_attack_as_of_q3_2024 STRING,
# MAGIC   -- owasp_llm_top_10_2025 STRING,
# MAGIC   -- owasp_ml_top_10_v0_3 STRING,
# MAGIC   -- nist_800_53_rev_5 STRING,
# MAGIC   -- nist_800_53_controls_mapping_rationale STRING,
# MAGIC   -- hitrust STRING,
# MAGIC   -- enisa_securing_ml_algorithms STRING,
# MAGIC   -- iso_42001_2023_controls_objectives_and_controls_annex_a STRING,
# MAGIC   -- iso_27001_2022_information_security_control_reference_annex_a STRING,
# MAGIC   -- eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns risk details consisting of risk id, system components, and the full risk title from Risks in AI system components table' 
# MAGIC RETURN 
# MAGIC -- Select the specified columns from the risks_in_ai_system_components table
# MAGIC SELECT
# MAGIC   risk_id,
# MAGIC   system_component,
# MAGIC   risk_name
# MAGIC FROM
# MAGIC   risks_in_ai_system_components;

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_components function
# MAGIC SELECT * FROM risks_in_ai_system_components()

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function that returns the total number of risks
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_components_count() RETURNS INT
# MAGIC COMMENT 'Returns the total number of risks'
# MAGIC     RETURN (SELECT COUNT(*) FROM risks_in_ai_system_components);

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select the total number of risks from the risks_in_ai_system_components_count function
# MAGIC SELECT risks_in_ai_system_components_count() AS result

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function that returns a table of risks based on the provided risk_id_param
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_for_component(risk_id_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   risk_id STRING, 
# MAGIC   system_component STRING, 
# MAGIC   risk STRING, 
# MAGIC   risk_name STRING,
# MAGIC   risk_description STRING, 
# MAGIC   mitigation_control_ids STRING, 
# MAGIC   mitigation_controls STRING, 
# MAGIC   revision STRING, 
# MAGIC   is_predictive_ml_models STRING, 
# MAGIC   is_rag_llms STRING, 
# MAGIC   is_fine_tuned_llms STRING, 
# MAGIC   is_pre_trained_llms STRING, 
# MAGIC   is_foundational_llms STRING, 
# MAGIC   is_external_models STRING, 
# MAGIC   initial_ai_risk_impacts STRING, 
# MAGIC   business_impacts STRING, 
# MAGIC   ai_novelty STRING, 
# MAGIC   mitre_atlas_as_of_q3_2024 STRING, 
# MAGIC   mitre_attack_as_of_q3_2024 STRING, 
# MAGIC   owasp_llm_top_10_2025 STRING, 
# MAGIC   owasp_ml_top_10_v0_3 STRING, 
# MAGIC   nist_800_53_rev_5 STRING, 
# MAGIC   nist_800_53_controls_mapping_rationale STRING, 
# MAGIC   hitrust STRING, 
# MAGIC   enisa_securing_ml_algorithms STRING, 
# MAGIC   iso_42001_2023_controls_objectives_and_controls_annex_a STRING, 
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING, 
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns all related risk of AI system components and all the details associated to each risk based on Risk Category and or Risk ID'
# MAGIC RETURN
# MAGIC -- Select all columns from the risks_in_ai_system_components table where the risk_id matches the provided parameter
# MAGIC SELECT * FROM risks_in_ai_system_components
# MAGIC WHERE risk_id rlike risk_id_param

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_for_component function
# MAGIC -- where the risk_id matches the pattern 'Raw Data'
# MAGIC SELECT * FROM risks_in_ai_system_for_component('Raw Data')

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_for_component function
# MAGIC -- where the risk_id matches the pattern 'Raw Data 1.10'
# MAGIC SELECT * FROM risks_in_ai_system_for_component('Raw Data 1.10')

# COMMAND ----------

# MAGIC %sql
# MAGIC -- This code creates a new function risks_in_ai_system_component_by_risk_id
# MAGIC -- The function takes a single parameter risk_id_param of type STRING
# MAGIC -- The function returns a table with all columns
# MAGIC -- The function returns all details for a risk in AI system components by risk id
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_component_by_risk_id(risk_id_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   risk_id STRING, 
# MAGIC   system_component STRING, 
# MAGIC   risk STRING, 
# MAGIC   risk_name STRING,
# MAGIC   risk_description STRING, 
# MAGIC   mitigation_control_ids STRING, 
# MAGIC   mitigation_controls STRING, 
# MAGIC   revision STRING, 
# MAGIC   is_predictive_ml_models STRING, 
# MAGIC   is_rag_llms STRING, 
# MAGIC   is_fine_tuned_llms STRING, 
# MAGIC   is_pre_trained_llms STRING, 
# MAGIC   is_foundational_llms STRING, 
# MAGIC   is_external_models STRING, 
# MAGIC   initial_ai_risk_impacts STRING, 
# MAGIC   business_impacts STRING, 
# MAGIC   ai_novelty STRING, 
# MAGIC   mitre_atlas_as_of_q3_2024 STRING, 
# MAGIC   mitre_attack_as_of_q3_2024 STRING, 
# MAGIC   owasp_llm_top_10_2025 STRING, 
# MAGIC   owasp_ml_top_10_v0_3 STRING, 
# MAGIC   nist_800_53_rev_5 STRING, 
# MAGIC   nist_800_53_controls_mapping_rationale STRING, 
# MAGIC   hitrust STRING, 
# MAGIC   enisa_securing_ml_algorithms STRING, 
# MAGIC   iso_42001_2023_controls_objectives_and_controls_annex_a STRING, 
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING, 
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns all details for a risk in AI system components risk_id'
# MAGIC RETURN
# MAGIC SELECT * FROM risks_in_ai_system_components
# MAGIC WHERE risk_id = risk_id_param

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_component_by_risk_id function
# MAGIC -- where the risk_id matches the pattern 'Datasets 3.1'
# MAGIC SELECT * from risks_in_ai_system_component_by_risk_id('Datasets 3.1')

# COMMAND ----------

# MAGIC %sql
# MAGIC -- This code creates a new function risks_in_ai_system_component_by_risk_name
# MAGIC -- The function takes a single parameter risk_name_param of type STRING
# MAGIC -- The function returns a table with all columns
# MAGIC -- The function returns all details for a risk in AI system components by risk name
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_component_by_risk_name(risk_name_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   risk_id STRING, 
# MAGIC   system_component STRING, 
# MAGIC   risk STRING, 
# MAGIC   risk_name STRING,
# MAGIC   risk_description STRING, 
# MAGIC   mitigation_control_ids STRING, 
# MAGIC   mitigation_controls STRING, 
# MAGIC   revision STRING, 
# MAGIC   is_predictive_ml_models STRING, 
# MAGIC   is_rag_llms STRING, 
# MAGIC   is_fine_tuned_llms STRING, 
# MAGIC   is_pre_trained_llms STRING, 
# MAGIC   is_foundational_llms STRING, 
# MAGIC   is_external_models STRING, 
# MAGIC   initial_ai_risk_impacts STRING, 
# MAGIC   business_impacts STRING, 
# MAGIC   ai_novelty STRING, 
# MAGIC   mitre_atlas_as_of_q3_2024 STRING, 
# MAGIC   mitre_attack_as_of_q3_2024 STRING, 
# MAGIC   owasp_llm_top_10_2025 STRING, 
# MAGIC   owasp_ml_top_10_v0_3 STRING, 
# MAGIC   nist_800_53_rev_5 STRING, 
# MAGIC   nist_800_53_controls_mapping_rationale STRING, 
# MAGIC   hitrust STRING, 
# MAGIC   enisa_securing_ml_algorithms STRING, 
# MAGIC   iso_42001_2023_controls_objectives_and_controls_annex_a STRING, 
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING, 
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns all details for a risk in AI system components by risk name'
# MAGIC RETURN
# MAGIC SELECT * FROM risks_in_ai_system_components
# MAGIC WHERE risk_name = risk_name_param

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_in_ai_system_component_by_risk_name function
# MAGIC -- where the risk_name matches 'Data poisoning'
# MAGIC SELECT * from risks_in_ai_system_component_by_risk_name('Data poisoning')

# COMMAND ----------

# MAGIC %md
# MAGIC # Databricks AI Mitigation Controls

# COMMAND ----------

# Read the Databricks AI Mitigation Controls data from a TSV file into a DataFrame
df_Databricks_AI_Mitigation_Controls = spark.read.format("csv") \
    .option("header", True) \
    .option("inferSchema", True) \
    .option("delimiter", "\t") \
    .load(f"{volume_path}/Databricks AI Security Framework - Databricks AI Mitigation Controls.tsv")

# Display the DataFrame
display(df_Databricks_AI_Mitigation_Controls)

# COMMAND ----------

# Select and rename columns from the DataFrame for the Databricks AI Mitigation Controls table
databricks_ai_mitigation_controls = df_Databricks_AI_Mitigation_Controls.selectExpr(
    "`Control ID` as mitigation_control_id",
    "`Control` as control",
    "`Risk ID` as risk_id",
    "`Description` as description",
    "`Databricks Shared Responsibility` as databricks_shared_responsibility",
    "`Databricks Product Reference` as databricks_product_reference",
    "`Databricks Documentation (AWS)` as databricks_documentation_aws",
    "`Databricks Documentation (Azure)` as databricks_documentation_azure",
    "`Databricks Documentation (GCP)` as databricks_documentation_gcp",
    "`DASF Revision` as dasf_revision",
    "`Security Control Type` as security_control_type",
    "`AI System Component Step` as ai_system_component_step",
    "`Security Analysis Tool (SAT)` as security_analysis_tool_sat",
    "`AI System Novelty` as ai_system_novelty",
    "`MITRE ATLAS as of Q3 2024` as mitre_atlas_q3_2024",
    "`MITRE ATTACK as of Q3 2024` as mitre_attack_q3_2024",
    "`OWASP LLM Top 10 2025` as owasp_llm_top_10_2025",
    "`OWASP ML Top 10 v0.3` as owasp_ml_top_10_v0_3",
    "`ISO 42001:2023 Controls Objectives and Controls (Annex A)` as iso_42001_2023_controls_objectives_controls_annex_a",
    "`ISO 27001:2022 Information Security Control Reference (Annex A)` as iso_27001_2022_information_security_control_reference_annex_a",
    "`NIST - 800- 53 - Rev 5` as nist_800_53_rev_5",
    "`HITRUST` as hitrust",
    "`ENISA’s Securing ML Algorithms` as enisa_securing_ml_algorithms",
    "`EU AI ACT` as eu_ai_act"
)

# Display the resulting DataFrame
display(databricks_ai_mitigation_controls)

# COMMAND ----------

# Write the databricks_ai_mitigation_controls DataFrame to a table with specified options
databricks_ai_mitigation_controls.write \
    .option("overwriteSchema", "true") \
    .option("description", "The 'risks_in_ai_system_components' table contains information about the risks associated with various AI system components as documented in Databricks AI Security Framework (DASF). It provides details on the identified risks, their descriptions, and the corresponding mitigation control measures. The table also includes information on the revision history of the  DSAF risks and whether the risks applies to predictive ML models, RAG LLMS, fine-tuned LLMS, pre-trained LLMS, foundational LLMS, or external models. Additionally, the table captures the initial AI risk impacts, business impacts, AI novelty, and the latest versions of MITRE Atlas, MITRE Attack, OWASP LLM Top 10, and OWASP ML Top 10. This table is crucial for understanding and managing the risks associated with our AI system components.") \
    .option("tags", "AI, Security, Controls") \
    .saveAsTable(f"{catalog}.{schema}.databricks_ai_mitigation_controls", mode="overwrite")

# COMMAND ----------

# MAGIC %sql
# MAGIC -- This code creates a new function databricks_ai_mitigation_controls
# MAGIC -- The function returns a table with selected columns
# MAGIC -- The function returns the mitigation control id, full control title, and each risk associated to each control
# MAGIC CREATE OR REPLACE FUNCTION databricks_ai_mitigation_controls() RETURNS TABLE (
# MAGIC   mitigation_control_id STRING,
# MAGIC   control STRING,
# MAGIC   risk_id STRING
# MAGIC   -- description STRING,
# MAGIC   -- databricks_shared_responsibility STRING,
# MAGIC   -- databricks_product_reference STRING,
# MAGIC   -- databricks_documentation_aws STRING,
# MAGIC   -- databricks_documentation_azure STRING,
# MAGIC   -- databricks_documentation_gcp STRING,
# MAGIC   -- dasf_revision STRING,
# MAGIC   -- security_control_type STRING,
# MAGIC   -- ai_system_component_step STRING,
# MAGIC   -- security_analysis_tool_sat STRING,
# MAGIC   -- ai_system_novelty STRING,
# MAGIC   -- mitre_atlas_q3_2024 STRING,
# MAGIC   -- mitre_attack_q3_2024 STRING,
# MAGIC   -- owasp_llm_top_10_2025 STRING,
# MAGIC   -- owasp_ml_top_10_v0_3 STRING,
# MAGIC   -- iso_42001_2023_controls_objectives_controls_annex_a STRING,
# MAGIC   -- iso_27001_2022_information_security_control_reference_annex_a STRING,
# MAGIC   -- nist_800_53_rev_5 STRING,
# MAGIC   -- hitrust STRING,
# MAGIC   -- enisa_securing_ml_algorithms STRING,
# MAGIC   -- eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns the mitigation control id, full control title, and each risk associated to each control' 
# MAGIC RETURN
# MAGIC SELECT
# MAGIC   mitigation_control_id,
# MAGIC   control,
# MAGIC   risk_id
# MAGIC   -- description,
# MAGIC   -- databricks_shared_responsibility,
# MAGIC   -- databricks_product_reference,
# MAGIC   -- databricks_documentation_aws,
# MAGIC   -- databricks_documentation_azure,
# MAGIC   -- databricks_documentation_gcp,
# MAGIC   -- dasf_revision,
# MAGIC   -- security_control_type,
# MAGIC   -- ai_system_component_step,
# MAGIC   -- security_analysis_tool_sat,
# MAGIC   -- ai_system_novelty,
# MAGIC   -- mitre_atlas_q3_2024,
# MAGIC   -- mitre_attack_q3_2024,
# MAGIC   -- owasp_llm_top_10_2025,
# MAGIC   -- owasp_ml_top_10_v0_3,
# MAGIC   -- iso_42001_2023_controls_objectives_controls_annex_a,
# MAGIC   -- iso_27001_2022_information_security_control_reference_annex_a,
# MAGIC   -- nist_800_53_rev_5,
# MAGIC   -- hitrust,
# MAGIC   -- enisa_securing_ml_algorithms,
# MAGIC   -- eu_ai_act
# MAGIC FROM
# MAGIC   databricks_ai_mitigation_controls;

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the databricks_ai_mitigation_controls function
# MAGIC SELECT * FROM databricks_ai_mitigation_controls()

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function databricks_ai_mitigation_controls_count
# MAGIC -- The function returns an integer representing the total count of AI mitigation controls
# MAGIC CREATE OR REPLACE FUNCTION databricks_ai_mitigation_controls_count() RETURNS INT
# MAGIC COMMENT 'Returns the total count of ai mitigation controls'
# MAGIC     RETURN (SELECT COUNT(*) FROM databricks_ai_mitigation_controls);

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select the total count of AI mitigation controls using the databricks_ai_mitigation_controls_count function
# MAGIC SELECT databricks_ai_mitigation_controls_count() AS result

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function databricks_ai_mitigation_control_by_mitigation_control_id
# MAGIC -- The function returns a table with details of the control for a given mitigation control id
# MAGIC CREATE OR REPLACE FUNCTION databricks_ai_mitigation_control_by_mitigation_control_id(mitigation_control_id_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   mitigation_control_id STRING,
# MAGIC   control STRING,
# MAGIC   risk_id STRING,
# MAGIC   description STRING,
# MAGIC   databricks_shared_responsibility STRING,
# MAGIC   databricks_product_reference STRING,
# MAGIC   databricks_documentation_aws STRING,
# MAGIC   databricks_documentation_azure STRING,
# MAGIC   databricks_documentation_gcp STRING,
# MAGIC   dasf_revision STRING,
# MAGIC   security_control_type STRING,
# MAGIC   ai_system_component_step STRING,
# MAGIC   security_analysis_tool_sat STRING,
# MAGIC   ai_system_novelty STRING,
# MAGIC   mitre_atlas_q3_2024 STRING,
# MAGIC   mitre_attack_q3_2024 STRING,
# MAGIC   owasp_llm_top_10_2025 STRING,
# MAGIC   owasp_ml_top_10_v0_3 STRING,
# MAGIC   iso_42001_2023_controls_objectives_controls_annex_a STRING,
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING,
# MAGIC   nist_800_53_rev_5 STRING,
# MAGIC   hitrust STRING,
# MAGIC   enisa_securing_ml_algorithms STRING,
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns the mitigation control id, full control title, risk_id, description, and all the details of the control for a given mitigation control id'
# MAGIC RETURN
# MAGIC SELECT * FROM databricks_ai_mitigation_controls
# MAGIC WHERE mitigation_control_id = mitigation_control_id_param

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all details of the mitigation control with the specified mitigation control id 'DASF 12'
# MAGIC SELECT * FROM databricks_ai_mitigation_control_by_mitigation_control_id('DASF 12')

# COMMAND ----------

# MAGIC %md
# MAGIC # AI Lifecycle Risks and Mitigation Control mapping

# COMMAND ----------

from pyspark.sql.functions import split, explode

# Split the 'mitigation_control_ids' column by commas and explode the resulting array into separate rows
risks_and_controls_df = risks_in_ai_system_components.withColumn("mitigation_control_id", explode(split(risks_in_ai_system_components["mitigation_control_ids"], ",")))

# Display the resulting DataFrame
display(risks_and_controls_df)

# COMMAND ----------

# Select the 'risk_id' and 'mitigation_control_id' columns from the DataFrame
# Write the DataFrame to a table with specified options
risks_and_controls_df.select("risk_id", "mitigation_control_id").write \
    .option("overwriteSchema", "true") \
    .option("description", "The risks_and_controls_mapping table provides a mapping between risk IDs and mitigation control IDs as documented in Databricks AI Security Framework (DASF). This table is essential for tracking and managing risks with their corresponding controls.  It allows for the identification of which mitigation controls are associated with each risk, enabling effective risk management and mitigation strategies. The risk_id column represents the unique identifier for each risk, while the mitigation_control_id column represents the unique identifier for each mitigation control. This table serves as a valuable resource for understanding the relationship between risks and their corresponding mitigation controls.") \
    .option("tags", "AI, Risks, Mitigation Components") \
    .saveAsTable(f"{catalog}.{schema}.risks_and_controls_mapping", mode="overwrite")

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the risks_and_controls_mapping table
# MAGIC SELECT * FROM risks_and_controls_mapping

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function to return mitigation controls by risk id
# MAGIC CREATE OR REPLACE FUNCTION databricks_ai_mitigation_controls_by_risk_id(risk_id_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   mitigation_control_id STRING,
# MAGIC   control STRING,
# MAGIC   risk_id STRING,
# MAGIC   description STRING,
# MAGIC   databricks_shared_responsibility STRING,
# MAGIC   databricks_product_reference STRING,
# MAGIC   databricks_documentation_aws STRING,
# MAGIC   databricks_documentation_azure STRING,
# MAGIC   databricks_documentation_gcp STRING,
# MAGIC   dasf_revision STRING,
# MAGIC   security_control_type STRING,
# MAGIC   ai_system_component_step STRING,
# MAGIC   security_analysis_tool_sat STRING,
# MAGIC   ai_system_novelty STRING,
# MAGIC   mitre_atlas_q3_2024 STRING,
# MAGIC   mitre_attack_q3_2024 STRING,
# MAGIC   owasp_llm_top_10_2025 STRING,
# MAGIC   owasp_ml_top_10_v0_3 STRING,
# MAGIC   iso_42001_2023_controls_objectives_controls_annex_a STRING,
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING,
# MAGIC   nist_800_53_rev_5 STRING,
# MAGIC   hitrust STRING,
# MAGIC   enisa_securing_ml_algorithms STRING,
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns mitigation controls with control id, full control title, risk_id, description, and all the details of the control for a given risk id'
# MAGIC RETURN
# MAGIC SELECT conrols.* 
# MAGIC FROM databricks_ai_mitigation_controls as conrols, risks_and_controls_mapping as risks_and_controls_mapping
# MAGIC WHERE risks_and_controls_mapping.risk_id = risk_id_param
# MAGIC and risks_and_controls_mapping.mitigation_control_id = conrols.mitigation_control_id

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Select all columns from the function databricks_ai_mitigation_controls_by_risk_id for a given risk id
# MAGIC SELECT * FROM databricks_ai_mitigation_controls_by_risk_id('Datasets 3.1')

# COMMAND ----------

# MAGIC %sql
# MAGIC -- Create a new function to return risks in AI system components by mitigation control id
# MAGIC CREATE OR REPLACE FUNCTION risks_in_ai_system_by_mitigation_controls_id(mitigation_controls_id_param STRING) 
# MAGIC RETURNS TABLE (
# MAGIC   risk_id STRING, 
# MAGIC   system_component STRING, 
# MAGIC   risk STRING, 
# MAGIC   risk_name STRING,
# MAGIC   risk_description STRING, 
# MAGIC   mitigation_control_ids STRING, 
# MAGIC   mitigation_controls STRING, 
# MAGIC   revision STRING, 
# MAGIC   is_predictive_ml_models STRING, 
# MAGIC   is_rag_llms STRING, 
# MAGIC   is_fine_tuned_llms STRING, 
# MAGIC   is_pre_trained_llms STRING, 
# MAGIC   is_foundational_llms STRING, 
# MAGIC   is_external_models STRING, 
# MAGIC   initial_ai_risk_impacts STRING, 
# MAGIC   business_impacts STRING, 
# MAGIC   ai_novelty STRING, 
# MAGIC   mitre_atlas_as_of_q3_2024 STRING, 
# MAGIC   mitre_attack_as_of_q3_2024 STRING, 
# MAGIC   owasp_llm_top_10_2025 STRING, 
# MAGIC   owasp_ml_top_10_v0_3 STRING, 
# MAGIC   nist_800_53_rev_5 STRING, 
# MAGIC   nist_800_53_controls_mapping_rationale STRING, 
# MAGIC   hitrust STRING, 
# MAGIC   enisa_securing_ml_algorithms STRING, 
# MAGIC   iso_42001_2023_controls_objectives_and_controls_annex_a STRING, 
# MAGIC   iso_27001_2022_information_security_control_reference_annex_a STRING, 
# MAGIC   eu_ai_act STRING
# MAGIC )
# MAGIC COMMENT 'Returns all related risks addressed in a AI system components and all the details associated to each risk by a given mitigation control id'
# MAGIC RETURN
# MAGIC SELECT risks.* 
# MAGIC FROM risks_in_ai_system_components as risks, risks_and_controls_mapping as risks_and_controls_mapping
# MAGIC WHERE risks_and_controls_mapping.mitigation_control_id = mitigation_controls_id_param
# MAGIC and risks_and_controls_mapping.risk_id = risks.risk_id

# COMMAND ----------

# MAGIC %sql 
# MAGIC -- Select all columns from the function risks_in_ai_system_by_mitigation_controls_id for a given mitigation control id
# MAGIC SELECT * FROM risks_in_ai_system_by_mitigation_controls_id('DASF 1')
