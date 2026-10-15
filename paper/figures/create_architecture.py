"""Reproduce editable SVG and embedded-font PDF architecture figures.

Run from any directory with Python and reportlab; no model/data inputs required.
Coordinates use points at the final IEEE column/text width.
"""
from pathlib import Path
from html import escape
import math
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor

ROOT = Path(__file__).resolve().parent
FONT = Path('C:/Windows/Fonts/arial.ttf')
pdfmetrics.registerFont(TTFont('Diagram', str(FONT)))
pdfmetrics.registerFont(TTFont('DiagramBold', 'C:/Windows/Fonts/arialbd.ttf'))

class Figure:
    def __init__(self, name, w, h):
        self.name, self.w, self.h = name, w, h
        self.pdf = canvas.Canvas(str(ROOT / (name + '.pdf')), pagesize=(w, h), initialFontName='Diagram')
        self.pdf.setTitle(name.replace('-', ' '))
        self.svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}pt" height="{h}pt" viewBox="0 0 {w} {h}">', '<rect width="100%" height="100%" fill="white"/>']
    def box(self, x, y, w, h, lines, fill='#eaf1f6', stroke='#3f6075', size=9, bold=False):
        self.pdf.setFillColor(HexColor(fill)); self.pdf.setStrokeColor(HexColor(stroke))
        self.pdf.setLineWidth(.8); self.pdf.roundRect(x,y,w,h,5,fill=1,stroke=1)
        self.svg.append(f'<rect x="{x}" y="{self.h-y-h}" width="{w}" height="{h}" rx="5" fill="{fill}" stroke="{stroke}" stroke-width=".8"/>')
        gap=size+3
        for i,line in enumerate(lines): self.text(x+w/2,y+h/2+(len(lines)-1)*gap/2-i*gap-size*.33,line,size,bold)
    def text(self,x,y,s,size=9,bold=False,anchor='middle',color='#172e40'):
        self.pdf.setFillColor(HexColor(color)); self.pdf.setFont('DiagramBold' if bold else 'Diagram',size)
        {'middle':self.pdf.drawCentredString,'start':self.pdf.drawString,'end':self.pdf.drawRightString}[anchor](x,y,s)
        self.svg.append(f'<text x="{x}" y="{self.h-y}" text-anchor="{anchor}" font-family="Arial,sans-serif" font-size="{size}" font-weight="{700 if bold else 400}" fill="{color}">{escape(s)}</text>')
    def line(self,points,color='#3f6075',dash=False,arrow=True):
        self.pdf.setStrokeColor(HexColor(color)); self.pdf.setFillColor(HexColor(color)); self.pdf.setLineWidth(.9)
        self.pdf.setDash([3,2] if dash else [])
        p=self.pdf.beginPath();p.moveTo(*points[0])
        for pt in points[1:]:p.lineTo(*pt)
        self.pdf.drawPath(p);self.pdf.setDash([])
        pts=' '.join(f'{x},{self.h-y}' for x,y in points)
        self.svg.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width=".9"'+(' stroke-dasharray="3 2"' if dash else '')+'/>')
        if arrow:
            x,y=points[-1];a=math.atan2(y-points[-2][1],x-points[-2][0]);r=4
            verts=[(x,y),(x-r*math.cos(a-.5),y-r*math.sin(a-.5)),(x-r*math.cos(a+.5),y-r*math.sin(a+.5))]
            p=self.pdf.beginPath();p.moveTo(*verts[0]);p.lineTo(*verts[1]);p.lineTo(*verts[2]);p.close();self.pdf.drawPath(p,fill=1,stroke=0)
            self.svg.append('<polygon points="'+' '.join(f'{xx},{self.h-yy}' for xx,yy in verts)+f'" fill="{color}"/>')
    def save(self):
        self.pdf.showPage();self.pdf.save();(ROOT/(self.name+'.svg')).write_text('\n'.join(self.svg+['</svg>']),encoding='utf8')

f=Figure('architecture-overview',510,244)
f.box(5,8,354,223,[],fill='#f6f9fb',stroke='#6f8796')
f.text(16,216,'TRUSTED WORKSTATION',10,True,'start')
f.text(436,216,'REMOTE SERVICES',10,True)
f.box(16,150,91,45,['Supported prompt','page hook'],size=10)
f.box(128,150,91,45,['Extension','background'],size=10)
f.box(240,150,107,45,['Local runtime','rules / NER / model'],size=9)
f.line([(107,174),(128,174)]);f.line([(219,174),(240,174)])
f.text(228,201,'loopback gRPC-Web',8)
f.box(128,87,91,39,['Native-messaging','supervisor'],fill='#ffffff',size=9)
f.line([(172,126),(172,148)],dash=True)
f.line([(219,106),(293,106),(293,148)],dash=True)
f.text(231,79,'manages bridge / runtime',8)
f.box(382,150,121,45,['Web-hosted LLM','receives original body'],fill='#fff2df',stroke='#997435',size=9)
f.line([(62,150),(62,136),(372,136),(372,174),(382,174)],color='#997435')
f.text(164,138,'ALLOW / WARN only; BLOCK stops the request',8,color='#77591e')
f.box(382,82,121,44,['Guarded update service','and parameter stream'],fill='#eaf4ed',stroke='#4d7657',size=9)
f.line([(382,105),(352,105),(352,157),(347,157)],color='#4d7657')
f.text(371,72,'versioned weights',8,color='#3b6748')
f.box(16,25,130,39,['Local budget ledger','and randomized report'],fill='#f2edf7',stroke='#78618d',size=9)
f.line([(253,150),(253,74),(81,74),(81,64)],color='#78618d')
f.box(382,25,121,39,['Telemetry collector','aggregate estimates'],fill='#f2edf7',stroke='#78618d',size=9)
f.line([(146,44),(382,44)],color='#78618d')
f.text(263,48,'randomized fields; no prompt text',8,color='#67517b')
f.text(264,29,'no telemetry-to-training path',8,True,color='#67517b')
f.save()

f=Figure('architecture-enforcement',245,188)
f.box(46,151,153,31,['Recognized outgoing prompt'],size=10)
f.box(46,103,153,31,['Local analysis and policy'],size=10)
f.line([(122,151),(122,134)])
f.box(5,47,108,38,['BLOCK / analysis failure','Cancel supported request'],fill='#faeeee',stroke='#925353',size=8.5)
f.box(132,47,108,38,['ALLOW / WARN','Forward original body'],fill='#fff2df',stroke='#997435',size=9)
f.line([(85,103),(59,85)],color='#925353');f.line([(160,103),(185,85)],color='#997435')
f.text(122,28,'WARN attempts a notice; acknowledgement is not awaited.',7.8)
f.text(122,13,'Stream fallback may use remaining layers; coverage can shrink.',7.7)
f.save()

f=Figure('architecture-updates',245,235)
f.box(28,194,189,32,['Supplied labelled training examples'],fill='#eaf4ed',stroke='#4d7657',size=9)
f.box(28,144,189,32,['Server computes candidate for exact base'],fill='#eaf4ed',stroke='#4d7657',size=9)
f.line([(122,194),(122,176)],color='#4d7657')
f.box(28,84,189,43,['Validate tensor / version contract','Apply strategy-configured guard'],fill='#eaf4ed',stroke='#4d7657',size=9)
f.line([(122,144),(122,127)],color='#4d7657')
f.box(5,14,109,45,['Reject: retain base','Record rejection'],fill='#faeeee',stroke='#925353',size=8.5)
f.box(132,14,108,45,['Publish atomically','Stream new weights'],fill='#eaf4ed',stroke='#4d7657',size=9)
f.line([(86,84),(59,59)],color='#925353');f.line([(162,84),(186,59)],color='#4d7657')
f.text(122,69,'guard + exact-base checks',8)
f.text(122,3,'Publication uses compare-and-swap and durable replay receipts.',7.6)
f.save()
