import json
import os
from datetime import datetime

def generate_html_report(json_file="reports/multilang_security_report.json", output_file="reports/security_report.html"):
    """
    Genera un reporte HTML interactivo a partir del archivo JSON de seguridad.
    
    Args:
        json_file: Ruta al archivo JSON con el reporte de seguridad
        output_file: Nombre del archivo HTML de salida
    """
    
    # Verificar que existe el archivo JSON
    if not os.path.exists(json_file):
        print(f"❌ Error: No se encuentra el archivo '{json_file}'")
        return False
    
    # Cargar datos del JSON
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            report_data = json.load(f)
        print(f"✅ Archivo JSON cargado: {len(report_data)} archivos encontrados")
    except json.JSONDecodeError as e:
        print(f"❌ Error al parsear JSON: {e}")
        return False
    except Exception as e:
        print(f"❌ Error al leer archivo: {e}")
        return False
    
    # Convertir los datos de Python a JavaScript
    report_data_json = json.dumps(report_data, indent=4, ensure_ascii=False)
    
    # Obtener fecha y hora actual
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Plantilla HTML completa
    html_template = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scanner Report</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .header h1 {{
            color: #2d3748;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header p {{
            color: #718096;
            font-size: 1.1em;
        }}

        .timestamp {{
            color: #a0aec0;
            font-size: 0.9em;
            margin-top: 10px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-card h3 {{
            color: #718096;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .stat-card.critical .number {{ color: #e53e3e; }}
        .stat-card.high .number {{ color: #dd6b20; }}
        .stat-card.medium .number {{ color: #d69e2e; }}
        .stat-card.safe .number {{ color: #38a169; }}

        .charts-section {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}

        .chart-container {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .chart-container h2 {{
            color: #2d3748;
            margin-bottom: 20px;
            font-size: 1.3em;
        }}

        .filters {{
            background: white;
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filters label {{
            color: #2d3748;
            font-weight: 600;
        }}

        .filters select, .filters input {{
            padding: 10px 15px;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: border-color 0.3s;
        }}

        .filters select:hover, .filters input:hover {{
            border-color: #667eea;
        }}

        .files-grid {{
            display: grid;
            gap: 20px;
        }}

        .file-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }}

        .file-card:hover {{
            transform: translateY(-3px);
        }}

        .file-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }}

        .file-name {{
            font-size: 1.4em;
            font-weight: bold;
            color: #2d3748;
        }}

        .badge {{
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .badge.critical {{
            background: #fed7d7;
            color: #c53030;
        }}

        .badge.high {{
            background: #feebc8;
            color: #c05621;
        }}

        .badge.medium {{
            background: #fefcbf;
            color: #975a16;
        }}

        .badge.safe {{
            background: #c6f6d5;
            color: #276749;
        }}

        .file-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
            padding: 15px;
            background: #f7fafc;
            border-radius: 10px;
        }}

        .info-item {{
            display: flex;
            flex-direction: column;
        }}

        .info-label {{
            color: #718096;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}

        .info-value {{
            color: #2d3748;
            font-weight: bold;
            font-size: 1.1em;
        }}

        .findings {{
            margin-top: 20px;
        }}

        .findings h4 {{
            color: #2d3748;
            margin-bottom: 15px;
            font-size: 1.1em;
        }}

        .finding {{
            background: #f7fafc;
            border-left: 4px solid #e2e8f0;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }}

        .finding.critical {{ border-left-color: #e53e3e; }}
        .finding.high {{ border-left-color: #dd6b20; }}
        .finding.medium {{ border-left-color: #d69e2e; }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .finding-type {{
            font-weight: bold;
            color: #2d3748;
            font-size: 1em;
        }}

        .finding-line {{
            background: #2d3748;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
        }}

        .finding-snippet {{
            background: #2d3748;
            color: #68d391;
            padding: 12px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .no-findings {{
            color: #38a169;
            font-style: italic;
            padding: 15px;
            background: #c6f6d5;
            border-radius: 8px;
        }}

        @media (max-width: 768px) {{
            .charts-section {{
                grid-template-columns: 1fr;
            }}
            
            .header h1 {{
                font-size: 1.8em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Scanner Report</h1>
            <p>Análisis de seguridad multilenguaje con ML e inspección estática</p>
            <div class="timestamp">Generado: {timestamp}</div>
        </div>

        <div class="stats-grid" id="stats"></div>

        <div class="charts-section">
            <div class="chart-container">
                <h2>Distribución por Severidad</h2>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h2>Archivos por Lenguaje</h2>
                <canvas id="languageChart"></canvas>
            </div>
        </div>

        <div class="filters">
            <label>Filtrar por:</label>
            <select id="severityFilter">
                <option value="all">Todas las severidades</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="SAFE">Safe</option>
            </select>
            <select id="languageFilter">
                <option value="all">Todos los lenguajes</option>
            </select>
            <input type="text" id="searchBox" placeholder="Buscar archivo...">
        </div>

        <div class="files-grid" id="filesGrid"></div>
    </div>

    <script>
        // Datos cargados dinámicamente desde JSON
        const reportData = {report_data_json};

        // Calcular estadísticas
        function calculateStats() {{
            const stats = {{
                critical: 0,
                high: 0,
                medium: 0,
                safe: 0,
                totalFiles: Object.keys(reportData).length
            }};

            Object.values(reportData).forEach(file => {{
                stats[file.verdict.toLowerCase()]++;
            }});

            return stats;
        }}

        // Renderizar estadísticas
        function renderStats() {{
            const stats = calculateStats();
            const statsHTML = `
                <div class="stat-card critical">
                    <h3>Critical</h3>
                    <div class="number">${{stats.critical}}</div>
                    <p>Archivos críticos</p>
                </div>
                <div class="stat-card high">
                    <h3>High Risk</h3>
                    <div class="number">${{stats.high}}</div>
                    <p>Riesgo alto</p>
                </div>
                <div class="stat-card medium">
                    <h3>Medium Risk</h3>
                    <div class="number">${{stats.medium}}</div>
                    <p>Riesgo medio</p>
                </div>
                <div class="stat-card safe">
                    <h3>Safe</h3>
                    <div class="number">${{stats.safe}}</div>
                    <p>Archivos seguros</p>
                </div>
            `;
            document.getElementById('stats').innerHTML = statsHTML;
        }}

        // Renderizar gráficos
        function renderCharts() {{
            const stats = calculateStats();
            
            // Gráfico de severidad
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Safe'],
                    datasets: [{{
                        data: [stats.critical, stats.high, stats.medium, stats.safe],
                        backgroundColor: ['#e53e3e', '#dd6b20', '#d69e2e', '#38a169']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom'
                        }}
                    }}
                }}
            }});

            // Gráfico de lenguajes
            const langCount = {{}};
            Object.values(reportData).forEach(file => {{
                langCount[file.language] = (langCount[file.language] || 0) + 1;
            }});

            new Chart(document.getElementById('languageChart'), {{
                type: 'bar',
                data: {{
                    labels: Object.keys(langCount),
                    datasets: [{{
                        label: 'Archivos',
                        data: Object.values(langCount),
                        backgroundColor: '#667eea'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{
                            display: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }}
                        }}
                    }}
                }}
            }});
        }}

        // Renderizar archivos
        function renderFiles(filter = {{}}) {{
            const grid = document.getElementById('filesGrid');
            let html = '';

            Object.entries(reportData).forEach(([filename, data]) => {{
                // Aplicar filtros
                if (filter.severity && filter.severity !== 'all' && data.verdict !== filter.severity) {{
                    return;
                }}
                if (filter.language && filter.language !== 'all' && data.language !== filter.language) {{
                    return;
                }}
                if (filter.search && !filename.toLowerCase().includes(filter.search.toLowerCase())) {{
                    return;
                }}

                const findingsHTML = data.findings.length > 0 
                    ? data.findings.map(f => `
                        <div class="finding ${{f.severity.toLowerCase()}}">
                            <div class="finding-header">
                                <span class="finding-type">${{f.type.replace(/_/g, ' ').toUpperCase()}}</span>
                                <span class="badge ${{f.severity.toLowerCase()}}">${{f.severity}}</span>
                                <span class="finding-line">Línea ${{f.line}}</span>
                            </div>
                            <div class="finding-snippet">${{f.snippet}}</div>
                        </div>
                    `).join('')
                    : '<div class="no-findings">✅ No se encontraron vulnerabilidades</div>';

                html += `
                    <div class="file-card">
                        <div class="file-header">
                            <div class="file-name">${{filename}}</div>
                            <span class="badge ${{data.verdict.toLowerCase()}}">${{data.verdict}}</span>
                        </div>
                        <div class="file-info">
                            <div class="info-item">
                                <span class="info-label">Lenguaje</span>
                                <span class="info-value">${{data.language.toUpperCase()}}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Score</span>
                                <span class="info-value">${{(data.score * 100).toFixed(1)}}%</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">ML Probability</span>
                                <span class="info-value">${{(data.ml_prob * 100).toFixed(1)}}%</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Hallazgos</span>
                                <span class="info-value">${{data.findings.length}}</span>
                            </div>
                        </div>
                        <div class="findings">
                            <h4>Vulnerabilidades detectadas:</h4>
                            ${{findingsHTML}}
                        </div>
                    </div>
                `;
            }});

            grid.innerHTML = html;
        }}

        // Poblar filtro de lenguajes
        function populateLanguageFilter() {{
            const languages = [...new Set(Object.values(reportData).map(f => f.language))];
            const select = document.getElementById('languageFilter');
            languages.forEach(lang => {{
                const option = document.createElement('option');
                option.value = lang;
                option.textContent = lang.toUpperCase();
                select.appendChild(option);
            }});
        }}

        // Event listeners
        document.getElementById('severityFilter').addEventListener('change', (e) => {{
            const filters = {{
                severity: e.target.value,
                language: document.getElementById('languageFilter').value,
                search: document.getElementById('searchBox').value
            }};
            renderFiles(filters);
        }});

        document.getElementById('languageFilter').addEventListener('change', (e) => {{
            const filters = {{
                severity: document.getElementById('severityFilter').value,
                language: e.target.value,
                search: document.getElementById('searchBox').value
            }};
            renderFiles(filters);
        }});

        document.getElementById('searchBox').addEventListener('input', (e) => {{
            const filters = {{
                severity: document.getElementById('severityFilter').value,
                language: document.getElementById('languageFilter').value,
                search: e.target.value
            }};
            renderFiles(filters);
        }});

        // Inicializar
        renderStats();
        renderCharts();
        populateLanguageFilter();
        renderFiles();
    </script>
</body>
</html>"""
    
    # Escribir el archivo HTML
    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        print(f"✅ Reporte HTML generado exitosamente: '{output_file}'")
        print(f"📊 Total de archivos analizados: {len(report_data)}")
        return True
    except Exception as e:
        print(f"❌ Error al escribir archivo HTML: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("🔒 GENERADOR DE REPORTE HTML DE SEGURIDAD")
    print("=" * 60)
    
    # Generar el reporte
    success = generate_html_report()
    
    if success:
        print("\n✨ ¡Proceso completado!")
        print("📄 Abre 'security_report.html' en tu navegador para ver el reporte")
    else:
        print("\n❌ Hubo un error al generar el reporte")
    
    print("=" * 60)