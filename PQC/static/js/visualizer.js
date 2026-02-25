class SecurityVisualizer {
    constructor() {
        this.loginForm = document.getElementById('login-form');
        this.overlay = document.getElementById('dashboard-overlay');
        this.closeBtn = document.getElementById('close-btn');
        this.replayBtn = document.getElementById('replay-btn');
        this.comparisonBody = document.getElementById('comparison-body');

        this.classicalSvg = document.getElementById('classical-svg');
        this.pqcSvg = document.getElementById('pqc-svg');

        this.nodeWidth = 220;
        this.nodeHeight = 50;
        this.verticalSpacing = 80;

        this.init();
    }

    init() {
        this.loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        this.closeBtn.addEventListener('click', () => this.overlay.classList.add('hidden'));
        this.replayBtn.addEventListener('click', () => this.startSimulation(this.lastData));
    }

    async handleLogin(e) {
        e.preventDefault();
        const formData = new FormData(this.loginForm);

        try {
            const response = await fetch('/simulate', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            this.lastData = data;

            this.overlay.classList.remove('hidden');
            this.startSimulation(data);
        } catch (err) {
            console.error("Login failed:", err);
            alert("Simulation failed to initialize.");
        }
    }

    startSimulation(data) {
        this.renderComparisonTable(data.comparison);

        this.classicalSvg.innerHTML = '';
        this.pqcSvg.innerHTML = '';

        this.animatePipeline('classical', data.classical, this.classicalSvg);
        this.animatePipeline('pqc', data.pqc, this.pqcSvg);
    }

    renderComparisonTable(comp) {
        const metrics = [
            { label: "Algorithm", key: "algo" },
            { label: "Public Key Size", key: "pk_size" },
            { label: "Encapsulation/Payload Size", key: "ct_size" },
            { label: "Quantum-Safe Status", key: "quantum_safe" }
        ];

        this.comparisonBody.innerHTML = metrics.map(m => `
            <tr>
                <td><strong>${m.label}</strong></td>
                <td class="text-classical">${comp.classical[m.key]}</td>
                <td class="text-pqc">${comp.pqc[m.key]}</td>
            </tr>
        `).join('');
    }

    async animatePipeline(type, steps, svg) {
        const nodes = [];
        const edges = [];

        // 1. Create Nodes
        steps.forEach((step, i) => {
            const x = 150; // Center X
            const y = 50 + (i * this.verticalSpacing);

            const nodeGrp = this.createNode(step, x, y, type);
            svg.appendChild(nodeGrp);
            nodes.push(nodeGrp);

            if (i > 0) {
                const prevY = 50 + ((i - 1) * this.verticalSpacing) + this.nodeHeight;
                const edge = this.createEdge(x, prevY, x, y);
                svg.appendChild(edge);
                edges.push(edge);
            }
        });

        // 2. Sequential Animation
        for (let i = 0; i < steps.length; i++) {
            // Highlight node
            nodes[i].querySelector('.node').classList.add('active');
            nodes[i].querySelector('.data-label').classList.replace('hidden', 'fade-in');

            await this.sleep(1200);

            // Draw edge to next
            if (edges[i]) {
                edges[i].classList.add('animate');
                await this.sleep(800);
            }
        }
    }

    createNode(step, x, y, type) {
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");

        const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        rect.setAttribute("x", x - this.nodeWidth / 2);
        rect.setAttribute("y", y);
        rect.setAttribute("width", this.nodeWidth);
        rect.setAttribute("height", this.nodeHeight);
        rect.setAttribute("rx", "10");
        rect.setAttribute("class", "node");

        const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
        text.setAttribute("x", x);
        text.setAttribute("y", y + 30);
        text.setAttribute("class", "node-text");
        text.textContent = step.label;

        const dataLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
        dataLabel.setAttribute("x", x + this.nodeWidth / 2 + 10);
        dataLabel.setAttribute("y", y + 30);
        dataLabel.setAttribute("class", "data-label hidden");
        dataLabel.textContent = step.data;

        g.appendChild(rect);
        g.appendChild(text);
        g.appendChild(dataLabel);

        return g;
    }

    createEdge(x1, y1, x2, y2) {
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        const d = `M ${x1} ${y1} L ${x2} ${y2}`;
        path.setAttribute("d", d);
        path.setAttribute("class", "edge");

        // Marker for arrow
        // (Simplified for now, can add <marker> if needed)
        return path;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new SecurityVisualizer();
});
