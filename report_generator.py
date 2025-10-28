from jinja2 import Template
import datetime

def generate_html_report(results, output_path):
    """
    Генерира красив HTML репорт от резултатите на сканирането.
    Очаква results да е списък от речници:
    [{"url": ..., "issues": [{"type": ..., "description": ..., "details": ...}, ...]}, ...]
    """

    html_template = """
    <html>
    <head>
        <meta charset="utf-8">
        <title>Safe Bug Bounty Scanner Report</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f8f9fa; color: #333; margin: 0; padding: 20px; }
            h1 { text-align: center; color: #007BFF; }
            .url-box { background: #fff; border: 1px solid #ddd; margin: 15px 0; padding: 15px; border-radius: 8px; }
            .url-title { font-size: 1.2em; font-weight: bold; color: #333; }
            .issue { background: #fdfdfd; border-left: 5px solid #007BFF; margin-top: 10px; padding: 10px; border-radius: 5px; }
            .issue h3 { margin: 0; color: #007BFF; }
            .meta { font-size: 0.9em; color: #555; }
            .footer { text-align: center; margin-top: 40px; color: #666; font-size: 0.85em; }
        </style>
    </head>
    <body>
        <h1>Safe Bug Bounty Scanner Report</h1>
        <p class="meta">Дата на генериране: {{ date }}</p>
        {% if results %}
            {% for item in results %}
                <div class="url-box">
                    <div class="url-title">🔗 {{ item.url }}</div>
                    {% if item.issues %}
                        {% for issue in item.issues %}
                            <div class="issue">
                                <h3>{{ issue.type }}</h3>
                                <p><strong>Описание:</strong> {{ issue.description }}</p>
                                {% if issue.details %}
                                    <p><strong>Детайли:</strong> {{ issue.details }}</p>
                                {% endif %}
                            </div>
                        {% endfor %}
                    {% else %}
                        <p>✅ Не са открити потенциални проблеми.</p>
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}
            <p>⚠️ Няма резултати за показване.</p>
        {% endif %}
        <div class="footer">
            Генериран от Safe Bug Bounty Scanner © {{ year }}
        </div>
    </body>
    </html>
    """

    template = Template(html_template)
    html = template.render(
        results=results,
        date=datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        year=datetime.datetime.now().year
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
