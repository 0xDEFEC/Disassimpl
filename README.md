<center><img src="disassimplBanner.png"></center>
<br/>
Disassimpl is a simple, multi-architecture (or at least it is uspposed to be), multi-mode disassembly utility powered by the Capstone Disassembly Engine found <a href="http://www.capstone-engine.org/">here.</a> It uses the Python's Capstone module and said module is accessed from the Python C API. This adds a few more dependencies, but avoids some of the annoying issues with the Capstone C API. If you're installing a disassembler, you probably won't mind installing a couple Python3 modules anyway, so. 
<br/><br/>
Please note, large portion of this utility has been untested, and some architectures may not even work. Considering this entire project is ~500 lines, I am even more confident it will break on some challenges. Furthermore, this isn't even a stable 'release.' I still have concepts in mind that shall be added, so I wouldn't call this even version 1.0.
