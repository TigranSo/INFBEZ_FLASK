
// Основной поиск
function searchDocuments() {
    const searchValue = document.getElementById("search").value.trim().toLowerCase();
    const documents = document.querySelectorAll('.search-result');
    const searchResultsContainer = document.getElementById("search-results");

    searchResultsContainer.innerHTML = "";

    documents.forEach(documentElement => {
        const documentName = documentElement.querySelector('.widget-26-job-title p').innerText.toLowerCase();
        if (documentName.includes(searchValue)) {
            searchResultsContainer.appendChild(documentElement);
            documentElement.style.display = 'block';
        } else {
            documentElement.style.display = 'none';
        }
    });
}
    

// Поиск по дисциплине
function showDocumentsByCategory(categoryName) {
    const documents = document.querySelectorAll('.search-result');
    const searchResultsContainer = document.getElementById('search-results');

    documents.forEach(documentElement => {
        const categoryElement = documentElement.querySelector('.location');
        if (categoryElement.innerText === categoryName) {
            searchResultsContainer.prepend(documentElement);
            documentElement.style.display = 'block';
            
        } else {
            documentElement.style.display = 'none';

            
        }
    });
}

document.querySelectorAll('.list-inline-item').forEach(categoryElement => {
    categoryElement.addEventListener('click', function() {
        const categoryName = categoryElement.innerText;
        showDocumentsByCategory(categoryName);
    });
});
    
