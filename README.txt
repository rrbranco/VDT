   Visual Data Trace v1.0 Alpha
   by 
	Rodrigo Rubira Branco (BSDaemon) - <rodrigo *noSPAM* risesecurity_org>
	Julio Auto - <julio *noSPAM* julioauto.com>


== Contents
1. Disclaimer
2. Package Contents
3. Usage
4. Known bugs

== 1. Disclaimer
The authors makes no guarantees regarding this tool's
effectiveness or reliability, being it on its development 
and testing stages.

Actual version was created for a Phrack Article
and is companion of such article.


== 2. Package Contents
a) vdt-tracer.dll <- The tracer, a WinDbg extension
b) VDT-GUI.exe <- The analyzer

== 3. Usage
Place 'vdt-tracer.dll' on your WinDbg extensions folder (the ...\winext\
directory). Load it in WinDbg with '.load vdt-tracer' and then start tracing
by issuing the command '!vdt_trace <filename>'.

Afterwards, analysis can be done by opening the resulting trace file in
VDT-GUI.exe.

== 4. Known bugs
There are likely many bugs. At this stage of development, they are, quite
frankly, expected. The most annoying one, perhaps, is the excessively long
time that VDT-GUI takes to load a big file (and traces tend to be pretty big).
Loading time reaches around 40 minutes with the file that the authors use to
test the application. This is not a bug per se, but rather a severe limitation
of Microsoft's ListBox control (all of the processing happens in reasonable
time, just the listbox display takes that long). Anyway, it's very annoying and
is a priority for future fixes and enhancements.