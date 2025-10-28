import csv

def parse_scope(csv_path):
    in_scope = []
    out_scope = []

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row or len(row) < 2:
                continue
            url, status = row[0].strip(), row[1].strip().lower()
            if status == "in":
                in_scope.append(url)
            else:
                out_scope.append(url)
    return in_scope, out_scope

