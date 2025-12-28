"""Simple export views - no query params, no conflicts"""
from django.http import HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
import json
import csv
from io import BytesIO

from .models import Scan


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_pdf_view(request, scan_id):
    """Export scan as PDF"""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER
    
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Check permissions
    if not (request.user == scan.user or request.user.is_staff):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    vulnerabilities = scan.vulnerabilities.all()
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24,
                                 textColor=colors.HexColor('#1f2937'), spaceAfter=30, alignment=TA_CENTER)
    elements.append(Paragraph("Security Scan Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Scan Info
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14,
                                   textColor=colors.HexColor('#3b82f6'), spaceAfter=12, spaceBefore=12)
    elements.append(Paragraph("Scan Information", heading_style))
    
    duration_str = 'N/A'
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
        duration_str = f"{duration_seconds:.2f}s"
    
    scan_info_data = [
        ['Scan ID:', str(scan.id)],
        ['Target:', scan.target],
        ['Status:', scan.status.upper()],
        ['Started:', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
        ['Completed:', scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else 'N/A'],
        ['Duration:', duration_str],
        ['Vulnerabilities Found:', str(scan.vulnerabilities_found)],
    ]
    
    scan_info_table = Table(scan_info_data, colWidths=[2*inch, 4.5*inch])
    scan_info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(scan_info_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Vulnerabilities
    if vulnerabilities.exists():
        elements.append(Paragraph("Vulnerability Details", heading_style))
        elements.append(Spacer(1, 0.1*inch))
        
        severity_colors = {
            'critical': colors.HexColor('#dc2626'),
            'high': colors.HexColor('#ea580c'),
            'medium': colors.HexColor('#f59e0b'),
            'low': colors.HexColor('#3b82f6'),
            'info': colors.HexColor('#6b7280')
        }
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            vuln_title = f"{idx}. {vuln.title} [{vuln.severity.upper()}]"
            vuln_style = ParagraphStyle('VulnTitle', parent=styles['Heading3'], fontSize=12,
                                       textColor=severity_colors.get(vuln.severity, colors.black), spaceAfter=6)
            elements.append(Paragraph(vuln_title, vuln_style))
            
            vuln_details = [
                ['Detector:', vuln.detector],
                ['URL:', (vuln.url[:100] + '...') if vuln.url and len(vuln.url) > 100 else (vuln.url or 'N/A')],
            ]
            
            if vuln.description:
                desc = vuln.description[:200] + '...' if len(vuln.description) > 200 else vuln.description
                vuln_details.append(['Description:', desc])
            
            if vuln.payload:
                payload = vuln.payload[:150] + '...' if len(vuln.payload) > 150 else vuln.payload
                vuln_details.append(['Payload:', payload])
            
            vuln_table = Table(vuln_details, colWidths=[1.5*inch, 5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9fafb')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.15*inch))
            
            if idx % 3 == 0 and idx < vulnerabilities.count():
                elements.append(PageBreak())
    else:
        elements.append(Paragraph("No vulnerabilities found.", styles['Normal']))
    
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.pdf"'
    return response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_json_view(request, scan_id):
    """Export scan as JSON"""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if not (request.user == scan.user or request.user.is_staff):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    vulnerabilities = scan.vulnerabilities.all()
    
    duration_seconds = None
    if scan.started_at and scan.completed_at:
        duration_seconds = (scan.completed_at - scan.started_at).total_seconds()
    
    data = {
        'scan': {
            'id': scan.id,
            'target': scan.target,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'duration': f"{duration_seconds:.2f}s" if duration_seconds else None,
            'vulnerabilities_found': scan.vulnerabilities_found,
        },
        'vulnerabilities': [
            {
                'title': v.title,
                'description': v.description,
                'severity': v.severity,
                'detector': v.detector,
                'url': v.url,
                'payload': v.payload,
                'evidence': v.evidence,
                'status_code': v.status_code,
            }
            for v in vulnerabilities
        ]
    }
    
    response = HttpResponse(json.dumps(data, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.json"'
    return response


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def export_csv_view(request, scan_id):
    """Export scan as CSV"""
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)
    
    if not (request.user == scan.user or request.user.is_staff):
        return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)
    
    vulnerabilities = scan.vulnerabilities.all()
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan-{scan.id}-report.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Title', 'Severity', 'Detector', 'URL', 'Description', 'Evidence'])
    
    for v in vulnerabilities:
        writer.writerow([
            v.title,
            v.severity,
            v.detector,
            v.url or '',
            v.description or '',
            v.evidence or ''
        ])
    
    return response
