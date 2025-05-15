document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('post-modal');
  const textarea = document.getElementById('post');
  const addPostBtn = document.getElementById('add-post-btn');
  const closeModalBtn = document.getElementById('close-modal-btn');
  const body = document.body;

  // Initialize custom file input functionality
  initializeCustomFileInput();

  // Initialize see more buttons
  initializeSeeMoreButtons();

  // Fetch username if needed
  const usernameDisplay = document.getElementById('username-display');
  if (usernameDisplay) {
    fetch('/api/username')
      .then(response => response.json())
      .then(data => {
        usernameDisplay.textContent = `Posting as: ${data.username || 'Anonymous'}`;
      })
      .catch(error => {
        console.error('Error fetching username:', error);
        usernameDisplay.textContent = 'Posting as: Anonymous';
      });
  }

  // Modal functionality
  if (addPostBtn && modal && closeModalBtn) {
    addPostBtn.addEventListener('click', openModal);
    closeModalBtn.addEventListener('click', closeModal);
    
    // Close modal when clicking outside or pressing Escape
    window.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
    
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();
    });
  }

  function openModal() {
    modal.style.display = 'block';
    textarea.focus();
    body.style.overflow = 'hidden';
  }

  function closeModal() {
    modal.style.display = 'none';
    body.style.overflow = 'auto';
    textarea.value = '';

    // Reset file input when closing modal
    const fileInputs = document.querySelectorAll('.custom-file-input input[type="file"]');
    fileInputs.forEach(input => {
      input.value = '';
      const parentContainer = input.closest('.custom-file-input');
      parentContainer.classList.remove('file-selected');
      const fileNameSpan = parentContainer.querySelector('.file-name');
      if (fileNameSpan) fileNameSpan.textContent = '';
    });
  }
  
  // Initialize comment functionality if we're on a page with comments
  initializeComments();
});

// Function to initialize see more buttons
function initializeSeeMoreButtons() {
  const seeMoreButtons = document.querySelectorAll('.see-more-btn');
  const MIN_LENGTH_TO_TRUNCATE = 150; // Minimum text length to show the "See more" button

  seeMoreButtons.forEach(button => {
    // Skip if the button doesn't have a previous element (truncated text container)
    const contentContainer = button.previousElementSibling;
    if (!contentContainer) {
      button.classList.add('hidden');
      return;
    }

    const textContent = contentContainer.textContent;

    // Only show see more button if the text is long enough
    if (!textContent || textContent.length < MIN_LENGTH_TO_TRUNCATE) {
      button.classList.add('hidden');
      return;
    }

    button.addEventListener('click', function () {
      contentContainer.classList.toggle('expanded');

      if (contentContainer.classList.contains('expanded')) {
        button.textContent = 'See less';
      } else {
        button.textContent = 'See more...';
      }
    });
  });
}

// Function to initialize custom file input
function initializeCustomFileInput() {
  const fileInputs = document.querySelectorAll('.custom-file-input input[type="file"]');

  fileInputs.forEach(input => {
    input.addEventListener('change', function () {
      const parentContainer = this.closest('.custom-file-input');
      const fileNameSpan = parentContainer.querySelector('.file-name');

      if (this.files && this.files.length > 0) {
        // Show the file name
        const fileName = this.files[0].name;
        if (fileNameSpan) {
          fileNameSpan.textContent = fileName;
          parentContainer.classList.add('file-selected');
        }
      } else {
        // Clear the file name
        if (fileNameSpan) {
          fileNameSpan.textContent = '';
          parentContainer.classList.remove('file-selected');
        }
      }
    });
  });
}

// Function to initialize comment functionality
function initializeComments() {
  const commentBtns = document.querySelectorAll('.comment-btn');
  if (!commentBtns.length) return; // Not on a page with comments
  
  console.log('Initializing comment functionality');
}
