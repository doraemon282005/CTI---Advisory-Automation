"""
Generates a representative Telecom Infrastructure Application Inventory Excel file.
This serves as both a starter template and an immediate test asset for the pipeline.
"""
from pathlib import Path
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def generate_inventory(output_path: str):
    wb = Workbook()
    ws = wb.active
    ws.title = "Application_Inventory"

    headers = [
        "Application Name",
        "Vendor",
        "Telecom Domain / Role",
        "Keywords / Aliases",
        "In-House Version / Deployment",
        "Criticality"
    ]

    # Sample telecom infrastructure applications
    sample_data = [
        ["Cisco IOS XR", "Cisco Systems", "IP Core & MPLS Transport Routing", "IOS XR, ASR 9000, NCS 5500", "7.5.2, 7.8.1", "Tier 1 - Mission Critical"],
        ["Juniper Junos OS", "Juniper Networks", "Carrier Edge & Peering Routing", "Junos, MX960, PTX10000", "22.2R3, 23.1R1", "Tier 1 - Mission Critical"],
        ["Ericsson Cloud Core (5GC / EPC)", "Ericsson", "Packet Core (AMF, SMF, UPF, MME)", "Cloud Packet Core, EPG, SGSN-MME", "24.Q1", "Tier 1 - Mission Critical"],
        ["Nokia NetAct", "Nokia", "Operations Support System (OSS / EMS)", "NetAct, NetAct Cloud, NMS", "22.8", "Tier 2 - Operational"],
        ["Oracle Database", "Oracle", "BSS / Billing Mediation & CDR Storage", "Oracle DB, 19c, RDBMS, TNS Listener", "19.18", "Tier 1 - Mission Critical"],
        ["Red Hat Enterprise Linux", "Red Hat", "Telco Cloud Base OS & NFVI", "RHEL, Red Hat Linux, rhel8, rhel9", "8.8, 9.2", "Tier 2 - Infrastructure"],
        ["VMware vCloud NFV", "VMware", "Telco Cloud Virtualization (VIM)", "vSphere, ESXi, NSX-T, vCloud Director", "7.0 U3, NSX-T 3.2", "Tier 1 - Infrastructure"],
        ["F5 BIG-IP", "F5 Networks", "Signaling & Gi-LAN Load Balancing (Diameter, DNS, CGNAT)", "BIG-IP, LTM, AFM, BIGIP", "16.1.3, 17.1.0", "Tier 1 - Mission Critical"],
        ["Palo Alto PAN-OS", "Palo Alto Networks", "Perimeter & Inter-Carrier Gi/SGi Firewall", "PAN-OS, PA-5450, PA-7000", "10.2.4-h2", "Tier 1 - Mission Critical"],
        ["Kamailio / OpenSIPS", "Open Source", "IMS Core SIP Proxy / VoLTE Signaling", "Kamailio, SIP Server, OpenSIPS", "5.7.2", "Tier 1 - Mission Critical"],
        ["Kubernetes / OpenShift", "Cloud Native Computing Foundation", "Containerized Network Functions (CNF) Platform", "Kubernetes, k8s, OpenShift, OCP", "1.28, 4.14", "Tier 1 - Infrastructure"],
        ["Apache Kafka", "Apache Software Foundation", "Real-Time CDR / Telemetry Streaming & Event Bus", "Kafka, Zookeeper, Strimzi", "3.6.0", "Tier 2 - Operational"],
        ["PostgreSQL", "PostgreSQL Global Development Group", "Subscriber Inventory & Provisioning DB", "Postgres, PostgreSQL", "15.4", "Tier 2 - Operational"],
        ["NGINX Plus", "F5 / NGINX", "5G Service-Based Architecture (SBA) API Gateway", "NGINX, nginx, NGINX Plus", "1.24", "Tier 2 - Infrastructure"]
    ]

    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="1B365D", end_color="1B365D", fill_type="solid")
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)

    thin_border = Border(
        left=Side(style='thin', color='D9D9D9'),
        right=Side(style='thin', color='D9D9D9'),
        top=Side(style='thin', color='D9D9D9'),
        bottom=Side(style='thin', color='D9D9D9')
    )

    ws.append(headers)
    ws.row_dimensions[1].height = 28

    for col_idx in range(1, len(headers) + 1):
        cell = ws.cell(row=1, column=col_idx)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_align

    data_font = Font(name="Calibri", size=10)
    for row_idx, row_data in enumerate(sample_data, start=2):
        ws.append(row_data)
        ws.row_dimensions[row_idx].height = 22
        for col_idx in range(1, len(row_data) + 1):
            cell = ws.cell(row=row_idx, column=col_idx)
            cell.font = data_font
            cell.border = thin_border
            if col_idx in [1, 2, 6]:
                cell.alignment = Alignment(horizontal="left", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)

    # Adjust column widths
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            val_str = str(cell.value or "")
            max_len = max(max_len, len(val_str))
        ws.column_dimensions[col_letter].width = min(max(max_len + 4, 15), 45)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_path)
    print(f"[Inventory] Sample application inventory created at: {output_path}")

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "inventory.xlsx"
    generate_inventory(out)
