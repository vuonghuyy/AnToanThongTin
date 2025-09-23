document.addEventListener('DOMContentLoaded', () => {

    // --- LOGIC CHO VIỆC NÉN FILE ---
    const filesToZipInput = document.getElementById('files-to-zip');
    const zipButton = document.getElementById('zip-button');

    zipButton.addEventListener('click', () => {
        const files = filesToZipInput.files;
        if (files.length === 0) {
            alert('Vui lòng chọn ít nhất một file để nén!');
            return;
        }

        const zip = new JSZip();

        // Thêm từng file vào đối tượng zip
        for (let i = 0; i < files.length; i++) {
            zip.file(files[i].name, files[i]);
        }

        // Tạo file zip và kích hoạt tải về
        zip.generateAsync({ type: 'blob' })
            .then(blob => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'archive.zip';
                a.click();
                URL.revokeObjectURL(a.href);
            })
            .catch(err => {
                console.error('Lỗi khi nén file:', err);
                alert('Đã xảy ra lỗi khi nén file.');
            });
    });

    // --- LOGIC CHO VIỆC GIẢI NÉN FILE ---
    const zipToUnzipInput = document.getElementById('zip-to-unzip');
    const unzippedFilesList = document.getElementById('unzipped-files-list');

    zipToUnzipInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) {
            return;
        }

        unzippedFilesList.innerHTML = '<i>Đang đọc file...</i>';

        const reader = new FileReader();
        reader.onload = (e) => {
            JSZip.loadAsync(e.target.result)
                .then(zip => {
                    unzippedFilesList.innerHTML = ''; // Xóa thông báo đang đọc
                    
                    if (Object.keys(zip.files).length === 0) {
                         unzippedFilesList.innerHTML = '<i>File zip này rỗng.</i>';
                         return;
                    }

                    // Lặp qua từng file trong zip
                    zip.forEach((relativePath, zipEntry) => {
                        // Bỏ qua các thư mục
                        if (zipEntry.dir) {
                            return;
                        }

                        // Tạo link tải về cho từng file
                        zipEntry.async('blob').then(blob => {
                            const a = document.createElement('a');
                            a.href = URL.createObjectURL(blob);
                            a.download = zipEntry.name;
                            a.textContent = zipEntry.name;
                            a.className = 'file-item';
                            unzippedFilesList.appendChild(a);
                        });
                    });
                })
                .catch(err => {
                    console.error('Lỗi khi giải nén:', err);
                    unzippedFilesList.innerHTML = '<i style="color:red;">File không hợp lệ hoặc bị lỗi.</i>';
                });
        };
        reader.readAsArrayBuffer(file);
    });

});