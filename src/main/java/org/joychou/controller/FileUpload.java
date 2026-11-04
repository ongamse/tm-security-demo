package org.joychou.controller;

import com.fasterxml.uuid.Generators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.HtmlUtils;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import java.util.regex.Pattern;

import org.joychou.security.SecurityUtil;


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
    private static String randomFilePath = "";

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
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            // The client file name is never used on disk: server generated name + validated extension.
            String ext = extensionOf(file.getOriginalFilename());
            if (ext == null) {
                redirectAttributes.addFlashAttribute("message", "upload failed");
                return "redirect:/file/status";
            }
            Path path = requireInUploadRoot(newUploadPath(ext));
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path.toString() + "'");

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

        // 判断文件后缀名是否在白名单内  校验1
        // Only the validated extension of the client file name is kept; the on-disk name is server generated.
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        String Suffix = extensionOf(multifile.getOriginalFilename());
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (white_suffix.equals(Suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error");
            return "Upload failed. Illeagl picture.";
        }

        Path safePath;
        try {
            safePath = newUploadPath(Suffix);
        } catch (IOException e) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = safePath.toString();
        File excelFile = convert(multifile, Suffix);



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
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            // Re-check containment right before writing; never follow or overwrite existing links/files.
            Path writePath = requireInUploadRoot(safePath);
            Files.write(writePath, bytes, StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Resolve a file name to a path directly inside UPLOADED_FOLDER.
     * Rejects names that contain path separators, "..", or otherwise escape the folder.
     */
    private static Path resolveUploadPath(String name) throws IOException {
        if (name == null || name.isEmpty() || name.indexOf('/') != -1 || name.indexOf('\\') != -1) {
            throw new IOException("Illegal file name");
        }
        try {
            Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
            Path target = base.resolve(name).normalize();
            if (!base.equals(target.getParent())) {
                throw new IOException("Illegal file name");
            }
            return target;
        } catch (InvalidPathException e) {
            throw new IOException("Illegal file name", e);
        }
    }

    // Only a short, lower-case alphanumeric extension is accepted from the client file name.
    private static final Pattern EXT_PATTERN = Pattern.compile("^\\.[a-z0-9]{1,8}$");

    /**
     * Return the validated, lower-case extension (with leading dot) of a client supplied
     * file name, or null if it does not have one. Nothing else of the name is ever used.
     */
    private static String extensionOf(String clientName) {
        if (clientName == null) {
            return null;
        }
        int idx = clientName.lastIndexOf('.');
        if (idx < 0) {
            return null;
        }
        String ext = clientName.substring(idx).toLowerCase();
        return EXT_PATTERN.matcher(ext).matches() ? ext : null;
    }

    /**
     * Build a server generated file path inside the upload folder. The name is a random UUID plus
     * a validated extension; no part of the client file name is used.
     */
    private static Path newUploadPath(String validatedExt) throws IOException {
        if (validatedExt == null || !EXT_PATTERN.matcher(validatedExt).matches()) {
            throw new IOException("Illegal file extension");
        }
        return requireInUploadRoot(resolveUploadPath(UUID.randomUUID().toString() + validatedExt));
    }

    /**
     * Resolve the real (symlink free) location of the given path and require that it is a regular
     * (non-link) entry directly inside the real upload root. Reject, never sanitise. Call this
     * immediately before the path is opened, written or deleted.
     */
    private static Path requireInUploadRoot(Path candidate) throws IOException {
        try {
            Path root = Paths.get(UPLOADED_FOLDER).toRealPath();
            Path abs = candidate.toAbsolutePath().normalize();
            Path parent = abs.getParent();
            Path name = abs.getFileName();
            if (parent == null || name == null) {
                throw new IOException("Illegal file path");
            }
            Path target = parent.toRealPath().resolve(name.toString());
            if (!target.startsWith(root) || !root.equals(target.getParent())) {
                throw new IOException("Illegal file path");
            }
            if (Files.isSymbolicLink(target)) {
                throw new IOException("Illegal file path");
            }
            return target;
        } catch (InvalidPathException e) {
            throw new IOException("Illegal file path", e);
        }
    }

    private void deleteFile(String filePath) {
        Path delPath;
        try {
            delPath = requireInUploadRoot(Paths.get(filePath));
        } catch (IOException e) {
            logger.info("Refuse to delete file outside upload folder");
            return;
        } catch (InvalidPathException e) {
            logger.info("Refuse to delete illegal file path");
            return;
        }
        File delFile = delPath.toFile();
        if(delFile.isFile() && delFile.exists()) {
            if (delFile.delete()) {
                logger.info("[+] " + filePath + " delete successfully!");
                return;
            }
        }
        logger.info(filePath + " delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, String validatedSuffix) throws Exception {
        UUID uuid = Generators.timeBasedGenerator().generate();
        // Server generated name + validated extension; containment re-checked right before creating.
        Path convPath = requireInUploadRoot(resolveUploadPath(uuid + validatedSuffix));
        randomFilePath = convPath.toString();
        // 随机生成一个同后缀名的文件
        File convFile = convPath.toFile();
        try {
            Files.write(convPath, multiFile.getBytes(), StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS);
        } catch (FileAlreadyExistsException e) {
            return null;
        }
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        // Re-check containment right before the file is opened for reading.
        File safeFile = requireInUploadRoot(file.toPath()).toFile();
        BufferedImage bi = ImageIO.read(safeFile);
        return bi != null;
    }
}
