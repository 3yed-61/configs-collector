<h1 id="configs-collector"><a aria-label="Anchor" href="#configs-collector" class="anchor">#</a> Configs-Collector</h1><h2 id="about"><a aria-label="Anchor" href="#about" class="anchor">#</a> About</h2><p>A Python-based tool designed to automatically collect, classify, and organize configuration files using customizable classification logic.</p>
<h2 id="features"><a aria-label="Anchor" href="#features" class="anchor">#</a> Features</h2><ul>
<li>Automatic scanning and ingestion of configuration files.</li><li>Classification module (<code>sub_classifier.py</code>) for applying custom rules.</li><li>Structured output folders for organized processing.</li><li>Easy to extend with additional classifiers or data types.</li></ul>
<h2 id="requirements"><a aria-label="Anchor" href="#requirements" class="anchor">#</a> Requirements</h2><ul>
<li>Python 3.8+</li><li>Install dependencies:<div data-code="pip install -r requirements.txt" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">pip install -r requirements.txt</code></pre>
      </div></li></ul>
<h2 id="installation"><a aria-label="Anchor" href="#installation" class="anchor">#</a> Installation</h2><p>Clone the repository:</p>
<div data-code="git clone https://github.com/3yed-61/configs-collector.git
cd configs-collector" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">git <span class="hljs-built_in">clone</span> https://github.com/3yed-61/configs-collector.git
<span class="hljs-built_in">cd</span> configs-collector</code></pre>
      </div><p>(Optional) Create a virtual environment:</p>
<div data-code="python3 -m venv venv
source venv/bin/activate    # Linux/macOS
venv\Scripts\activate     # Windows" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">python3 -m venv venv
<span class="hljs-built_in">source</span> venv/bin/activate    <span class="hljs-comment"># Linux/macOS</span>
venv\Scripts\activate     <span class="hljs-comment"># Windows</span></code></pre>
      </div><p>Install dependencies:</p>
<div data-code="pip install -r requirements.txt" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">pip install -r requirements.txt</code></pre>
      </div><h2 id="usage"><a aria-label="Anchor" href="#usage" class="anchor">#</a> Usage</h2><p>Run the classifier script:</p>
<div data-code="python sub_classifier.py --input path/to/configs --output classified_output/" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">python sub_classifier.py --input path/to/configs --output classified_output/</code></pre>
      </div><p>Arguments:</p>
<ul>
<li><code>--input</code> : Path to config files or directory</li><li><code>--output</code>: Destination folder for classified configs</li></ul>
<h2 id="example"><a aria-label="Anchor" href="#example" class="anchor">#</a> Example</h2><div data-code="python sub_classifier.py --input raw-configs/ --output classified_output/" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">python sub_classifier.py --input raw-configs/ --output classified_output/</code></pre>
      </div><h2 id="development"><a aria-label="Anchor" href="#development" class="anchor">#</a> Development</h2><ol>
<li>Fork the repository</li><li>Create a feature branch:<div data-code="git checkout -b feature/my-new-classifier" class="code-block-wrapper">
        <button title="Copy code" class="code-copy-btn">📋</button>
        <pre style="cursor: pointer;"><code class="hljs language-bash">git checkout -b feature/my-new-classifier</code></pre>
      </div></li><li>Commit changes and submit a Pull Request with a clear explanation.</li></ol>
<h2 id="contributing"><a aria-label="Anchor" href="#contributing" class="anchor">#</a> Contributing</h2><p>Contributions are welcome.<br>Please ensure:</p>
<ul>
<li>Clear explanation of changes</li><li>Tests (if applicable)</li><li>Clean and readable code</li></ul>
<h2 id="license"><a aria-label="Anchor" href="#license" class="anchor">#</a> License</h2><p>This project is licensed under the Apache License 2.0.</p>
<h2 id="contact"><a aria-label="Anchor" href="#contact" class="anchor">#</a> Contact</h2><p>Open an Issue in the repository for questions, bugs, or suggestions.</p>
