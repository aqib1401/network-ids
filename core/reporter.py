import logging
import json
import csv
import os
import time
from datetime import datetime
import matplotlib.pyplot as plt

class ReportGenerator:
    def __init__(self, output_dir="output/reports"):
        self.output_dir = output_dir
        self.logger = logging.getLogger("ReportGenerator")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_reports(self, stats, alerts, config):
        """Generates HTML, CSV, and JSON reports."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"report_{timestamp}"
        
        self._generate_json(stats, alerts, base_filename)
        self._generate_csv(alerts, base_filename)
        self._generate_html(stats, alerts, config, base_filename)
        
        return os.path.join(self.output_dir, f"{base_filename}.html")

    def _generate_json(self, stats, alerts, filename):
        data = {
            'stats': stats,
            'alerts': alerts,
            'generated_at': str(datetime.now())
        }
        path = os.path.join(self.output_dir, f"{filename}.json")
        with open(path, 'w') as f:
            json.dump(data, f, indent=4)

    def _generate_csv(self, alerts, filename):
        path = os.path.join(self.output_dir, f"{filename}.csv")
        if not alerts:
            return
            
        keys = alerts[0].keys()
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(alerts)

    def _generate_html(self, stats, alerts, config, filename):
        # Generate charts
        self._create_charts(stats, filename)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>NIDS Report - {datetime.now().strftime("%Y-%m-%d %H:%M")}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                .section {{ margin-bottom: 30px; border: 1px solid #ddd; padding: 20px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
                th {{ background-color: #f4f4f4; }}
                .alert-Critical {{ background-color: #ffdddd; }}
                .alert-High {{ background-color: #fff3cd; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .stat-box {{ background: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; }}
                .charts {{ display: flex; justify-content: space-around; flex-wrap: wrap; }}
                img {{ max-width: 100%; height: auto; margin: 10px; border: 1px solid #eee; }}
            </style>
        </head>
        <body>
            <h1>Network Intrusion Detection System Report</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-box">
                        <h3>Total Packets</h3>
                        <p>{stats['total_packets']}</p>
                    </div>
                    <div class="stat-box">
                        <h3>Duration</h3>
                        <p>{stats['duration']:.2f} seconds</p>
                    </div>
                    <div class="stat-box">
                        <h3>Total Alerts</h3>
                        <p>{len(alerts)}</p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Traffic Analysis</h2>
                <div class="charts">
                    <img src="{filename}_protocols.png" alt="Protocol Distribution">
                    <img src="{filename}_top_ips.png" alt="Top Source IPs">
                </div>
            </div>

            <div class="section">
                <h2>Threat Alerts</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Source IP</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for alert in alerts:
            ts = datetime.fromtimestamp(alert['timestamp']).strftime('%H:%M:%S')
            html_content += f"""
                        <tr class="alert-{alert['severity']}">
                            <td>{ts}</td>
                            <td>{alert['severity']}</td>
                            <td>{alert['type']}</td>
                            <td>{alert['src_ip']}</td>
                            <td>{alert['description']}</td>
                        </tr>
            """
            
        html_content += """
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Top Talkers (Source IPs)</h2>
                <table>
                    <thead><tr><th>IP Address</th><th>Packet Count</th></tr></thead>
                    <tbody>
        """
        
        for ip, count in stats['top_src_ips']:
            html_content += f"<tr><td>{ip}</td><td>{count}</td></tr>"
            
        html_content += """
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        """
        
        path = os.path.join(self.output_dir, f"{filename}.html")
        with open(path, 'w') as f:
            f.write(html_content)

    def _create_charts(self, stats, filename):
        # Protocol Pie Chart
        if stats['protocols']:
            plt.figure(figsize=(6, 6))
            plt.pie(stats['protocols'].values(), labels=stats['protocols'].keys(), autopct='%1.1f%%')
            plt.title("Protocol Distribution")
            plt.savefig(os.path.join(self.output_dir, f"{filename}_protocols.png"))
            plt.close()
        
        # Top IPs Bar Chart
        if stats['top_src_ips']:
            plt.figure(figsize=(10, 6))
            ips, counts = zip(*stats['top_src_ips'])
            plt.bar(ips, counts)
            plt.title("Top Source IPs")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, f"{filename}_top_ips.png"))
            plt.close()
