package org.joychou.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.joychou.security.SecurityUtil;
import org.joychou.security.UploadPaths;
import org.joychou.util.WebUtils;


/**
 * File upload.
 *
 * @author JoyChou @ 2018-08-15
 */
@Controller
@RequestMapping("/file")
public class FileUpload {

    // Save the uploaded file to this folder
    private static final String UPLOADED_FOLDER = "/tmp/";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    // Extensions accepted by the upload endpoints (lower case, no dot)
    private static final Set<String> PIC_EXTENSIONS = new HashSet<>(Arrays.asList("jpg", "png", "jpeg", "gif", "bmp", "ico"));
    private static final Set<String> ANY_EXTENSIONS = new HashSet<>(Arrays.asList("jpg", "png", "jpeg", "gif", "bmp", "ico",
            "txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "zip"));

    // uplaod any file
    @GetMapping("/any")
    public String index() {
        return "upload"; // return upload.html page
    }

    // only allow to upload pictures
    @GetMapping("/pic")
    public String uploadPic() {
        return "uploadPic"; // return uploadPic.html page
    }

    @PostMapping("/upload")
    public String singleFileUpload(@RequestParam("file") MultipartFile file,
                                   RedirectAttributes redirectAttributes) {
        if (file.isEmpty()) {
            // 赋值给uploadStatus.html里的动态参数message
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
            return "redirect:/file/status";
        }

        try {
            // Stored name is generated server side; the client file name is never used in a path
            String ext = UploadPaths.allowedExtension(file.getOriginalFilename(), ANY_EXTENSIONS);
            if (ext == null) {
                redirectAttributes.addFlashAttribute("message", "upload failed: file type not allowed");
                return "redirect:/file/status";
            }
            byte[] bytes = file.getBytes();
            Path path = UploadPaths.newUploadPath(UPLOADED_FOLDER, ext);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path.getFileName() + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error(e.toString());
        }

        return "redirect:/file/status";
    }

    @GetMapping("/status")
    public String uploadStatus() {
        return "uploadStatus";
    }

    // only upload picture
    @PostMapping("/upload/picture")
    @ResponseBody
    public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
        if (multifile.isEmpty()) {
            return "Please select a file to upload";
        }

        String fileName = multifile.getOriginalFilename();

        // 判断文件后缀名是否在白名单内  校验1
        // The extension is mapped to a constant from the allowlist; the client name is never used in a path.
        String ext = UploadPaths.allowedExtension(fileName, PIC_EXTENSIONS);
        if (ext == null) {
            logger.error("[-] Suffix error: " + WebUtils.sanitizeLog(fileName));
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = "." + ext;
        String mimeType = multifile.getContentType(); // 获取MIME类型

        Path finalPath;
        Path tempPath;
        try {
            finalPath = UploadPaths.newUploadPath(UPLOADED_FOLDER, ext);
            tempPath = UploadPaths.newUploadPath(UPLOADED_FOLDER, ext);
        } catch (IOException e) {
            logger.error("[-] Illegal upload path");
            return "Upload failed. Illeagl picture.";
        }
        String filePath = finalPath.getFileName().toString();
        File excelFile = convert(multifile, tempPath);


        // 判断MIME类型是否在黑名单内 校验2
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + WebUtils.sanitizeLog(mimeType));
                deleteFile(tempPath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(tempPath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Save under the server generated name only
            byte[] bytes = multifile.getBytes();
            Files.write(finalPath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(finalPath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", WebUtils.sanitizeLog(Suffix), WebUtils.sanitizeLog(mimeType));
        logger.info("[+] Successfully uploaded {}", WebUtils.sanitizeLog(filePath));
        return String.format("You successfully uploaded '%s'", WebUtils.htmlEncode(filePath));
    }

    /**
     * Delete a server generated upload path (never a client supplied one).
     */
    private void deleteFile(Path delPath) {
        if (delPath == null) {
            return;
        }
        Path base;
        try {
            base = Paths.get(UPLOADED_FOLDER).toRealPath();
        } catch (IOException | InvalidPathException e) {
            logger.info("Upload folder unavailable, delete skipped");
            return;
        }
        Path normalized = delPath.toAbsolutePath().normalize();
        if (!normalized.startsWith(base) || !base.equals(normalized.getParent())) {
            logger.info("Path outside upload folder, delete skipped");
            return;
        }
        try {
            // Atomic delete of the validated Path (a symlink is removed, never followed)
            if (Files.deleteIfExists(normalized)) {
                logger.info("[+] {} delete successfully!", WebUtils.sanitizeLog(normalized.getFileName().toString()));
                return;
            }
        } catch (IOException e) {
            logger.debug("Delete failed: {}", e.toString());
        }
        logger.info("{} delete failed!", WebUtils.sanitizeLog(normalized.getFileName().toString()));
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, Path tempPath) throws Exception {
        // 随机生成一个同后缀名的文件 (server generated path)
        File convFile = tempPath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
        }
        try (FileOutputStream fos = new FileOutputStream(convFile)) {
            fos.write(multiFile.getBytes());
        }
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
