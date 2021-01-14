class MiFooter extends HTMLElement {
    connectedCallback() {
        this.innerHTML = /* html */
            `Copyright &copy; 2021 Jesus Emmanuel Mejia Barona `;
    }
}
customElements.define("mi-footer", MiFooter);
