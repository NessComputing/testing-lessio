/**
 * Copyright (C) 2011-2012 Ness Computing, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.nesscomputing.testing.lessio;

import static java.lang.String.format;
import static java.lang.Thread.currentThread;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.security.Permission;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.nesscomputing.logging.Log;

/**
 * A {@link SecurityManager} to spotlight and minimize IO access while allowing
 * fine-grained control access to IO resoucres.
 *
 * This class was designed to draw attention to any IO (file and network) your
 * test suite may perform under the hood. IO not only slows down your test
 * suite, but unit tests that accidentally modify their environment may result
 * to flakey builds.
 *
 * Should a unit test need to perform IO, you may grant fine-grained permission
 * by annotating the container class with {@link AllowDNSResolution},
 * {@link AllowExternalProcess}, {@link AllowLocalFileAccess},
 * {@link AllowNetworkAccess}, or {@link AllowNetworkMulticast}. Some of these
 * annotations allow further refinement via parameters.
 *
 * <i>Usage.</i> To use the {@link LessIOSecurityManager}, you must set the
 * "java.security.manager" system property to
 * "com.nesscomputing.testing.lessio.LessIOSecurityManager", or your subclass.
 *
 * <i>Usage via command-line arguments.</i> You may add
 * "-Djava.security.manager=com.nesscomputing.testing.lessio.LessIOSecurityManager"
 * to your command-line invocation of the JVM to use this class as your
 * {@link SecurityManager}.
 *
 * <i>Usage via Ant.</i> You may declare the "java.security.manager" system
 * property in the "junit" element of your "build.xml" file. You <b>must</b> set
 * the "fork" property to ensure a new JVM, with this class as the
 * {@link SecurityManager} is utilized.
 *
 * <pre>
 * {@code
 * <junit fork="true">
 *   <sysproperty key="java.security.manager" value="com.nesscomputing.testing.lessio.LessIOSecurityManager" />
 *   ...
 * </junit>
 * }
 * </pre>
 *
 * <i>Performance.</i> Circa late 2010, the {@link LessIOSecurityManager}'s
 * impact on the performance of our test suite was less than 1.00%.
 *
 * @see {@link AllowDNSResolution}, {@link AllowExternalProcess},
 *      {@link AllowLocalFileAccess}, {@link AllowNetworkAccess}, and
 *      {@link AllowNetworkMulticast}
 */
public class LessIOSecurityManager extends SecurityManager {

  private static final Log LOG = Log.findLog();
  protected static final String JAVA_HOME = System.getProperty("java.home");
  protected static final String PATH_SEPARATOR = System.getProperty("path.separator");

  // Updated at SecurityManager init and again at every ClassLoader init.
  protected static final AtomicReference<List<String>> CP_PARTS =
          new AtomicReference<List<String>>(getClassPath());

  protected static final String TMP_DIR = System.getProperty("java.io.tmpdir").replaceFirst("/$", "");
  private static final Set<Class<?>> whitelistedClasses = ImmutableSet.<Class<?>>of(
                                                            java.lang.ClassLoader.class,
                                                            java.net.URLClassLoader.class);

  private final int lowestEphemeralPort = Integer.getInteger("ness.testing.low-ephemeral-port", Integer.getInteger("kawala.testing.low-ephemeral-port", 32768));
  private final int highestEphemeralPort = Integer.getInteger("ness.testing.high-ephemeral-port", Integer.getInteger("kawala.testing.high-ephemeral-port", 65535));
  private final Set<Integer> allocatedEphemeralPorts = Sets.newSetFromMap(Maps.<Integer, Boolean>newConcurrentMap());
  private final boolean reporting = Boolean.getBoolean("ness.testing.security-manager.reporting");

  /**
   * Any subclasses that override this method <b>must</b> include any Class<?>
   * elements returned by {@link LessIOSecurityManager#getWhitelistedClasses()}.
   * The recommended pattern is:
   * <blockquote><pre>
   * {@code
   private final Set<Class<?>> whitelistedClasses = ImmutableSet.<Class<?>>builder()
                                                      .addAll(parentWhitelistedClasses)
                                                      .add(javax.crypto.Cipher.class)
                                                      .add(javax.xml.xpath.XPathFactory.class)
                                                      .build();
   protected Set<Class<?>> getWhitelistedClasses() { return whitelistedClasses; }
   }
   </pre></blockquote>
   */
  protected Set<Class<?>> getWhitelistedClasses() {
    return whitelistedClasses;
  }

  private static ImmutableList<String> getClassPath() {
      return ImmutableList.copyOf(System.getProperty("java.class.path").split(PATH_SEPARATOR));
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static boolean hasAnnotations(final Class<?> clazz, final Class<?> ... annotations)
  {
      Preconditions.checkArgument(clazz != null, "clazz argument can not be null!");
      Preconditions.checkArgument(annotations != null && annotations.length > 0, "at least one annotation must be present");

      // Check class and parent classes.
      Class<?> currentClazz = clazz;
      while (currentClazz != null) {
          for (Class annotation : annotations) {
              if (currentClazz.getAnnotation(annotation) != null) {
                  return true;
              }
          }
          currentClazz = currentClazz.getSuperclass();
      }

      return false;
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static <T> T findAnnotation(final Class<?> clazz, final Class<T> annotation)
  {
      Preconditions.checkArgument(clazz != null, "clazz argument can not be null!");
      Preconditions.checkArgument(annotation != null, "annotation must be present");

      // Check class and parent classes.
      Class<?> currentClazz = clazz;
      while (currentClazz != null) {
          final T a = (T) currentClazz.getAnnotation((Class) annotation);
          if (a != null) {
              return a;
          }
          currentClazz = currentClazz.getSuperclass();
      }

      return null;

  }


  // {{ Allowed only via {@link @AllowNetworkAccess}, {@link @AllowDNSResolution}, or {@link @AllowNetworkMulticast})
  protected void checkDNSResolution(Class<?>[] classContext) throws CantDoItException {
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
            return hasAnnotations(input, AllowDNSResolution.class, AllowNetworkMulticast.class, AllowNetworkListen.class, AllowNetworkAccess.class);
        }

        @Override
        public String toString() {
          return String.format("@AllowDNSResolution permission");
        }
      });
    }
  }

  protected void checkNetworkEndpoint(final String host, final int port, final String description) throws CantDoItException {
    Class<?>[] classContext = getClassContext();

    if (port == -1) {
      checkDNSResolution(classContext);
      return;
    }

    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
          String [] endpoints = null;
          final AllowNetworkAccess access = findAnnotation(input, AllowNetworkAccess.class);
          if (access != null) {
              endpoints = access.endpoints();
          }
          if (endpoints == null) {
            return false;
          }

          for (String endpoint : endpoints) {
            String[] parts = endpoint.split(":");
            String portAsString = Integer.toString(port);
            if ((parts[0].equals(host) && parts[1].equals(portAsString))
                || (parts[0].equals("*") && parts[1].equals(portAsString))
                || (parts[0].equals(host) && parts[1].equals("*"))
                || (parts[0].equals(host) && parts[1].equals("0") && allocatedEphemeralPorts.contains(port))) {
              return true;
            }
          }
          return false;
        }

        @Override
        public String toString() {
          return String.format("@AllowNetworkAccess permission for %s:%d (%s)",
              host, port, description);
        }
      });
    }
  }

  @Override
  public void checkAccept(String host, int port) throws CantDoItException {
    checkNetworkEndpoint(host, port, "accept");
  }

  @Override
  public void checkConnect(String host, int port, Object context) throws CantDoItException {
    checkNetworkEndpoint(host, port, "connect");
  }

  @Override
  public void checkConnect(String host, int port) throws CantDoItException {
    checkNetworkEndpoint(host, port, "connect");
  }

  @Override
  public void checkListen(final int port) throws CantDoItException {
    Class<?>[] classContext = getClassContext();
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
          int [] ports = null;
          final AllowNetworkListen a = findAnnotation(input, AllowNetworkListen.class);
          if (a != null) {
              ports = a.ports();
          }
          if (ports == null) {
            return false;
        }

          for (int p : ports) {
            if (p == 0 && ((port >= lowestEphemeralPort) && (port <= highestEphemeralPort))) { // Check for access to ephemeral ports
              p = port;
              allocatedEphemeralPorts.add(port);
            }
            if (p == port) {
              return true;
            }
          }
          return false;
        }

        @Override
        public String toString() { return String.format("@AllowNetworkListen permission for port %d", port); }
      });
    }
  }

  @Override
  public void checkMulticast(InetAddress maddr) throws CantDoItException {
    Class<?>[] classContext = getClassContext();
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
            return hasAnnotations(input, AllowNetworkMulticast.class);
        }

        @Override
        public String toString() {
          return String.format("@AllowNetworkMulticast permission");
        }
      });
    }
  }

  @Override
  public void checkMulticast(InetAddress maddr, byte ttl) throws CantDoItException {
    checkMulticast(maddr);
  }

  // }}

  // {{ Allowed only via {@link @AllowLocalFileAccess}
  protected void checkFileAccess(final String file, final String description) throws CantDoItException {
    Class<?>[] classContext = getClassContext();
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      if (file.startsWith(JAVA_HOME)) {
        // Files in JAVA_HOME are always allowed
        return;
      }

      // Ant's JUnit task writes to /tmp/junitXXX
      if (file.startsWith("/dev/random") || file.startsWith("/dev/urandom") || file.startsWith("/tmp/junit")) {
         return;
      }

      /*
       * Although this is an expensive operation, it needs to be here, in a
       * suboptimal location to avoid ClassCircularityErrors that can occur when
       * attempting to load an anonymous class.
       */
      for (String part : CP_PARTS.get()) {
        if (file.startsWith(part)) {
          // Files in the CLASSPATH are always allowed
          return;
        }
      }

      try {
        checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
          @Override
          public boolean apply(Class<?> input) {
            String [] paths = null;
            final AllowLocalFileAccess a = findAnnotation(input, AllowLocalFileAccess.class);

            if (a != null) {
                paths = a.paths();
            }
            if (paths == null) {
              return false;
            }

            for (String p : paths) {
              if ((p.equals("*"))
                  || (p.equals(file))
                  || (p.contains("%TMP_DIR%") && (file.startsWith(p.replaceAll("%TMP_DIR%", TMP_DIR))))
                  || (p.startsWith("*") && p.endsWith("*") && file.contains(p.split("\\*")[1]))
                  || (p.startsWith("*") && file.endsWith(p.replaceFirst("^\\*", "")))
                  || (p.endsWith("*") && file.startsWith(p.replaceFirst("\\*$", "")))) {
                return true;
              }
            }
            return false;
          }

          @Override
          public String toString() {
            return String.format("@AllowLocalFileAccess for %s (%s)", file,
                description);
          }
        });
      } catch (CantDoItException e) {
        throw e;
      }
    }
  }

  public void checkFileDescriptorAccess(final FileDescriptor fd,
      final String description) throws CantDoItException {
    Class<?>[] classContext = getClassContext();
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
          // AllowExternalProcess and AllowNetworkAccess imply @AllowLocalFileAccess({"%FD%"}),
          // since it's required.
          if (hasAnnotations(input, AllowExternalProcess.class, AllowNetworkAccess.class)) {
              return true;
          }

          String [] paths = null;
          final AllowLocalFileAccess a = findAnnotation(input, AllowLocalFileAccess.class);

          if (a != null) {
              paths = a.paths();
          }

          if (paths == null) {
            return false;
          }

          for (String p : paths) {
            if (p.equals("%FD%")) {
              return true;
            }
          }
          return false;
        }

        @Override
        public String toString() {
          return String.format(
              "@AllowLocalFileAccess for FileDescriptor(%s) (%s)", fd,
              description);
        }
      });
    }
  }

  @Override
  public void checkRead(String file, Object context) {
    checkFileAccess(file, "read");
  }

  @Override
  public void checkRead(String file) {
    checkRead(file, null);
  }

  @Override
  public void checkRead(final FileDescriptor fd) {
    checkFileDescriptorAccess(fd, "read");
  }

  @Override
  public void checkDelete(final String file) {
    checkFileAccess(file, "delete");
  }

  @Override
  public void checkWrite(FileDescriptor fd) {
    checkFileDescriptorAccess(fd, "write");
  }

  @Override
  public void checkWrite(String file) {
    checkFileAccess(file, "write");
  }
  // }}

  // {{ Allowed only via {@link @AllowExternalProcess}
  @Override
  public void checkExec(final String cmd) throws CantDoItException {
    Class<?>[] classContext = getClassContext();
    if (traceWithoutExplicitlyAllowedClass(classContext)) {
      checkClassContextPermissions(classContext, new Predicate<Class<?>>() {
        @Override
        public boolean apply(Class<?> input) {
            return hasAnnotations(input, AllowExternalProcess.class);
        }

        @Override
        public String toString() {
          return String.format("@AllowExternalProcess for %s (exec)", cmd);
        }
      });
    }
  }
  // }}

  // {{ Closely Monitored
  @Override
  public void checkExit(int status) {
    LOG.info("%s: exit(%d)", currentTest(getClassContext()), status);
  }

  @Override
  public void checkLink(String lib) {
    LOG.info("%s: System.loadLibrary(\"%s\")", currentTest(getClassContext()), lib);
  }

  @Override
  public void checkAwtEventQueueAccess() {
    LOG.info("%s: AwtEventQueue Access", currentTest(getClassContext()));
  }

  @Override
  public void checkPrintJobAccess() {
    LOG.info("%s: PrintJob Access", currentTest(getClassContext()));
  }

  @Override
  public void checkSystemClipboardAccess() {
    LOG.info("%s: SystemClipboard Access", currentTest(getClassContext()));
  }

  @Override
  public boolean checkTopLevelWindow(Object window) {
    LOG.info("%s: checkTopLevelWindow aka AWTPermission(\"showWindowWithoutWarningBanner\")", currentTest(getClassContext()));
    return true;
  }

  // }}

  // {{ Always Allowed
  @Override public void checkAccess(Thread t) {}

  @Override public void checkAccess(ThreadGroup g) {}

  @Override public void checkMemberAccess(Class<?> clazz, int which) {}

  @Override public void checkPackageAccess(String pkg) {}

  @Override public void checkPackageDefinition(String pkg) {}

  @Override public void checkSetFactory() {}

  @Override public void checkCreateClassLoader() {
      // This is re-set on classloader creation in case the classpath has changed.
      // In particular, Maven's Surefire booter changes the classpath after the security
      // manager has been initialized.
      CP_PARTS.set(getClassPath());
  }

  @Override public void checkPropertiesAccess() {}

  @Override public void checkPropertyAccess(String key) {}

  @Override public void checkSecurityAccess(String target) {}
  // }}

  // {{ Undecided -- Can these be called in the real functions' stead?
  @Override
  public void checkPermission(Permission perm, Object context) {}

  @Override
  public void checkPermission(Permission perm) {}
  // }}

  private boolean isClassWhitelisted(Class<?> clazz) {
    if (getWhitelistedClasses().contains(clazz)) {
      return true;
    }

    Class<?> enclosingClass = clazz.getEnclosingClass();
    if (enclosingClass != null) {
      return isClassWhitelisted(enclosingClass);
    }

    return false;
  }

  private boolean traceWithoutExplicitlyAllowedClass(Class<?>[] classContext) {
    for (Class<?> clazz : classContext) {
      if (isClassWhitelisted(clazz)) {
        return false;
      }
    }
    return true;
  }

  private void checkClassContextPermissions(final Class<?>[] classContext,
		  final Predicate<Class<?>> classAuthorized) throws CantDoItException {
    // Only check permissions when we're running in the context of a JUnit test.
    boolean encounteredTestMethodRunner = false;
    for (Class<?> clazz : classContext) {
      if (clazz.getName().equals("org.junit.runners.ParentRunner")
          || clazz.getName().equals("org.junit.internal.runners.statements.RunAfters")
          || clazz.getName().equals("org.junit.internal.runners.statements.RunBefores")) {
        encounteredTestMethodRunner = true;
      }
    }
    if (!encounteredTestMethodRunner) {
      return;
    }

    for (Class<?> clazz : classContext) {
      if (classAuthorized.apply(clazz)) {
        return;
      }
    }

    // No class on the stack trace is properly authorized, throw an exception.
    CantDoItException e = new CantDoItException(String.format("No class in the class context satisfies %s", classAuthorized));

    if (this.reporting) {
      StackTraceElement testClassStackFrame = currentTest(classContext);
      String testName = "unknown test";
      if (testClassStackFrame != null) {
        testName = format("%s.%s():%d", testClassStackFrame.getClassName(), testClassStackFrame.getMethodName(), testClassStackFrame.getLineNumber());
      }
      LOG.error("%s: No %s at %s", testName, classAuthorized, testName);
      for (StackTraceElement el : currentThread().getStackTrace()) {
        LOG.trace("%s: Stack: %s.%s():%d", testName, el.getClassName(), el.getMethodName(), el.getLineNumber());
      }
      for (Class<?> cl : classContext) {
        LOG.trace("%s: Class Context: %s %s", testName, cl.getCanonicalName(), cl);
      }
    }

    throw e;
  }

  public StackTraceElement currentTest(Class<?>[] classContext) {
    // The first class right before TestMethodRunner in the class context
    // array is the class that contains our test.
    Class<?> testClass = null;
    for (Class<?> clazz : classContext) {
      if (clazz.getName().equals("org.junit.runners.ParentRunner")
          || clazz.getName().equals("org.junit.internal.runners.statements.RunAfters")
          || clazz.getName().equals("org.junit.internal.runners.statements.RunBefores")) {
        break;
      }
      testClass = clazz;
    }

    final StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();

    StackTraceElement testClassStackFrame = null;
    for (StackTraceElement el : stackTrace) {
      if (el.getClassName().equals(testClass.getCanonicalName())) {
        testClassStackFrame = el;
      }
    }

    return testClassStackFrame;
  }

  public static class CantDoItException extends RuntimeException {
    private static final long serialVersionUID = -8858380898538847118L;

    public CantDoItException() {
    }

    public CantDoItException(String s) {
      super(s);
    }

    public CantDoItException(String s, CantDoItException e) {
      super(s, e);
    }
  }
}
