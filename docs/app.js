// App logic - Tab and command management
console.log('App started');

const SECTIONS = Object.keys(COMMANDS_DB);
const NAV = document.getElementById('nav');

SECTIONS.forEach(section => {
    const btn = document.createElement('button');
    btn.className = 'tab-btn';
    btn.textContent = section.replace(/_/g, ' ').toUpperCase();
    btn.id = `tab-${section}`;
    btn.onclick = () => showTab(section);
    NAV.appendChild(btn);
});

function showTab(sectionName) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    
    const section = document.getElementById(sectionName);
    if (section) {
        section.classList.add('active');
        const btn = document.getElementById(`tab-${sectionName}`);
        if (btn) btn.classList.add('active');
        
        const grid = document.getElementById(`grid-${sectionName}`);
        if (grid) renderCommands(sectionName, grid);
    }
}

function renderCommands(sectionName, grid) {
    const commands = COMMANDS_DB[sectionName] || [];
    let html = '';
    
    commands.forEach(cmd => {
        const teamClass = cmd.team.toLowerCase();
        const escapeCmd = cmd.cmd.replace(/'/g, "\\'").replace(/"/g, '\\"');
        
        html += `
            <div class="card ${teamClass}">
                <div class="card-header">
                    <div class="card-title">${cmd.title}</div>
                    <span class="team team-${teamClass}">${cmd.team}</span>
                </div>
                <div class="desc">${cmd.desc}</div>
                <div class="cmd">${escapeHtml(cmd.cmd)}</div>
                <button class="copy" onclick="copyCommand('${escapeCmd}')">Copy</button>
            </div>
        `;
    });
    
    grid.innerHTML = html;
}

function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function copyCommand(cmd) {
    const unescapedCmd = cmd.replace(/\\'/g, "'").replace(/\\"/g, '"');
    navigator.clipboard.writeText(unescapedCmd).then(() => {
        const toast = document.getElementById('toast');
        toast.textContent = 'Copied!';
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2000);
    }).catch(() => alert('Copy failed'));
}

document.addEventListener('DOMContentLoaded', () => {
    SECTIONS.forEach(section => {
        const grid = document.getElementById(`grid-${section}`);
        if (grid) renderCommands(section, grid);
    });
    if (SECTIONS.length > 0) showTab(SECTIONS[0]);
});
