import pandas as pd

def get_mitre_info(tech_id: str):
    df = pd.read_csv("data/mitre_info.csv")
    row = df[df["tech_id"] == tech_id]
    if len(row):
        row = row.iloc[0]
        return {
            "tech_name": str(row["tech_name"]).lower().strip(),
            "tactics": [str(item).strip().lower() for item in row["tactics"].split(",")],
            "description": row["description"]
        }
    else:
        return None